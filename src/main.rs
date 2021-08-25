use defmt_decoder::Table;
use serialport::{self, FlowControl, Parity, StopBits};
use std::path::PathBuf;
use structopt::StructOpt;

/// Serial errors
#[derive(Debug, thiserror::Error)]
pub enum SerialError {
    #[error("Invalid parity requested \"{0}\"")]
    InvalidParityString(String),
    #[error("Invalid stop bits requested \"{0}\"")]
    InvalidStopBitsString(String),
    #[error("Defmt data not found")]
    DefmtDataNotFound,
}

fn try_to_serial_parity(parity: &str) -> Result<Parity, SerialError> {
    match parity {
        "odd" => Ok(Parity::Odd),
        "even" => Ok(Parity::Even),
        "none" => Ok(Parity::None),
        _ => Err(SerialError::InvalidParityString(parity.to_owned())),
    }
}

fn try_to_serial_stop_bits(stop_bits: &str) -> Result<StopBits, SerialError> {
    match stop_bits {
        "1" => Ok(StopBits::One),
        "2" => Ok(StopBits::Two),
        _ => Err(SerialError::InvalidStopBitsString(stop_bits.to_owned())),
    }
}

#[derive(Debug, StructOpt)]
#[structopt()]
struct Opts {
    /// Path to the elf file with defmt metadata
    #[structopt(name = "elf", required_unless_one(&["list-ports"]))]
    elf: Option<PathBuf>,

    /// Path to the uart port device
    #[structopt(name = "port", required_unless_one(&["list-ports"]))]
    port: Option<String>,

    /// Serial port baudrate. Defaults to 115200.
    #[structopt(long, short = "s")]
    baudrate: Option<u32>,

    /// Serial port stop bits number. Defaults to 1.
    #[structopt(long, parse(try_from_str=try_to_serial_stop_bits))]
    stop_bits: Option<StopBits>,

    /// Serial port parity configuration. Defaults to None.
    #[structopt(long, parse(try_from_str=try_to_serial_parity))]
    parity: Option<Parity>,

    /// Disables FW version check.
    #[structopt(long, short = "d")]
    disable_version_check: bool,

    /// Lists the available serial ports and exits.
    #[structopt(long)]
    list_ports: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::from_args();

    if opts.list_ports {
        let available_ports = serialport::available_ports()?;
        for port in available_ports {
            println!("{:?}", port);
        }
        return Ok(());
    }

    let verbose = false;
    defmt_decoder::log::init_logger(verbose, |_| true);

    let elf_data = std::fs::read(&opts.elf.unwrap())?;
    let table = Table::parse(&elf_data)?.ok_or(SerialError::DefmtDataNotFound)?;
    let locs = table.get_locations(&elf_data)?;

    let locs = if table.indices().all(|idx| locs.contains_key(&(idx as u64))) {
        Some(locs)
    } else {
        log::warn!("(BUG) location info is incomplete; it will be omitted from the output");
        None
    };

    let mut port = serialport::new(opts.port.unwrap(), opts.baudrate.unwrap_or(115200u32))
        .parity(opts.parity.unwrap_or(Parity::None))
        .stop_bits(opts.stop_bits.unwrap_or(StopBits::One))
        .flow_control(FlowControl::None)
        .open()?;
    port.set_timeout(std::time::Duration::from_millis(100))?;

    let mut buffer = [0; 1024];
    let mut frames = vec![];
    loop {
        let count = match port.read(&mut buffer[..]) {
            Ok(count) => Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(0),
            Err(error) => Err(error),
        }?;

        if count == 0 {
            continue;
        }

        frames.extend_from_slice(&buffer[..count]);

        loop {
            match table.decode(&frames) {
                Ok((frame, consumed)) => {
                    // NOTE(`[]` indexing) all indices in `table` have already been
                    // verified to exist in the `locs` map
                    let loc = locs.as_ref().map(|locs| &locs[&frame.index()]);

                    let (mut file, mut line, mut mod_path) = (None, None, None);
                    if let Some(loc) = loc {
                        let relpath = &loc.file;
                        file = Some(relpath.display().to_string());
                        line = Some(loc.line as u32);
                        mod_path = Some(loc.module.clone());
                    }

                    // Forward the defmt frame to our logger.
                    defmt_decoder::log::log_defmt(
                        &frame,
                        file.as_deref(),
                        line,
                        mod_path.as_deref(),
                    );

                    let num_frames = frames.len();
                    frames.rotate_left(consumed);
                    frames.truncate(num_frames - consumed);
                }
                Err(defmt_decoder::DecodeError::UnexpectedEof) => break,
                Err(defmt_decoder::DecodeError::Malformed) => {
                    log::error!("failed to decode defmt data: {:x?}", frames);
                    // Remove one byte and try again
                    frames.rotate_left(1);
                    frames.truncate(frames.len() - 1);
                }
            }
        }
    }
}
