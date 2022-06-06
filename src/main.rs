use defmt_decoder::Table;
use defmt_decoder::{DecodeError, Frame, Locations, StreamDecoder};
use serialport::{self, FlowControl, Parity, StopBits};
use std::env;
use std::path::Path;
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

    /// Shows defmt parsing errors. By default these are ignored.
    #[structopt(long, short = "d")]
    display_parsing_errors: bool,

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

    let current_dir = &env::current_dir()?;

    let elf_data = std::fs::read(&opts.elf.unwrap())?;
    let (table, locations) = extract_defmt_info(&elf_data)?;
    let table = table.unwrap();

    let mut port = serialport::new(opts.port.unwrap(), opts.baudrate.unwrap_or(115200u32))
        .parity(opts.parity.unwrap_or(Parity::None))
        .stop_bits(opts.stop_bits.unwrap_or(StopBits::One))
        .flow_control(FlowControl::None)
        .open()?;
    port.set_timeout(std::time::Duration::from_millis(100))?;

    let mut decoder_and_encoding = (table.new_stream_decoder(), table.encoding());

    let mut read_buf = [0; 1024];
    loop {
        let num_bytes_read = match port.read(&mut read_buf) {
            Ok(count) => Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(0),
            Err(error) => Err(error),
        }?;

        if num_bytes_read != 0 {
            let (stream_decoder, encoding) = &mut decoder_and_encoding;
            stream_decoder.received(&read_buf[..num_bytes_read]);

            match decode_and_print_defmt_logs(
                &mut **stream_decoder,
                locations.as_ref(),
                current_dir,
                encoding.can_recover(),
            ) {
                Ok(_) => {}
                Err(error) => {
                    if opts.display_parsing_errors {
                        log::error!("Error parsing uart data: {}", error);
                    }
                }
            }
        }
    }
}

fn extract_defmt_info(elf_bytes: &[u8]) -> anyhow::Result<(Option<Table>, Option<Locations>)> {
    let defmt_table = match env::var("PROBE_RUN_IGNORE_VERSION").as_deref() {
        Ok("true") | Ok("1") => defmt_decoder::Table::parse_ignore_version(elf_bytes)?,
        _ => defmt_decoder::Table::parse(elf_bytes)?,
    };

    let mut defmt_locations = None;

    if let Some(table) = defmt_table.as_ref() {
        let locations = table.get_locations(elf_bytes)?;

        if !table.is_empty() && locations.is_empty() {
            log::warn!("insufficient DWARF info; compile your program with `debug = 2` to enable location info");
        } else if table
            .indices()
            .all(|idx| locations.contains_key(&(idx as u64)))
        {
            defmt_locations = Some(locations);
        } else {
            log::warn!("(BUG) location info is incomplete; it will be omitted from the output");
        }
    }

    Ok((defmt_table, defmt_locations))
}

fn decode_and_print_defmt_logs(
    stream_decoder: &mut dyn StreamDecoder,
    locations: Option<&Locations>,
    current_dir: &Path,
    encoding_can_recover: bool,
) -> anyhow::Result<()> {
    loop {
        match stream_decoder.decode() {
            Ok(frame) => forward_to_logger(&frame, locations, current_dir),
            Err(DecodeError::UnexpectedEof) => break,
            Err(DecodeError::Malformed) => match encoding_can_recover {
                // if recovery is impossible, abort
                false => return Err(DecodeError::Malformed.into()),
                // if recovery is possible, skip the current frame and continue with new data
                true => continue,
            },
        }
    }

    Ok(())
}

fn forward_to_logger(frame: &Frame, locations: Option<&Locations>, current_dir: &Path) {
    let (file, line, mod_path) = location_info(frame, locations, current_dir);
    defmt_decoder::log::log_defmt(frame, file.as_deref(), line, mod_path.as_deref());
}

fn location_info(
    frame: &Frame,
    locations: Option<&Locations>,
    current_dir: &Path,
) -> (Option<String>, Option<u32>, Option<String>) {
    locations
        .map(|locations| &locations[&frame.index()])
        .map(|location| {
            let path = if let Ok(relpath) = location.file.strip_prefix(&current_dir) {
                relpath.display().to_string()
            } else {
                location.file.display().to_string()
            };
            (
                Some(path),
                Some(location.line as u32),
                Some(location.module.clone()),
            )
        })
        .unwrap_or((None, None, None))
}
