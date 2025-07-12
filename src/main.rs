use std::io::{BufReader, Read};
use std::fs::File;
use anyhow::Result;
use clap::Parser;

static BYTE_SIZE: usize = 8;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    file: String
}

struct DsStore {
    name: String,
    children: Vec<DsStore>,
    indet_length: usize,
}

struct DsStoreParser {
    file_signature: Vec<u8>,
    record_terminator: Vec<u8>,
    block_size: usize,
    root_offset_location: usize,
    root_offset_location_check: usize,
    index_padding: usize,
}

impl DsStore {
    pub fn print(&self) {
        println!("{}", self.name);

        for child in self.children.iter() {
            child.print_recurse(self.indet_length);
        }
    }

    fn print_recurse(&self, indent: usize) {
        print!("{:<1$}", " ", indent);
        print!("{}", self.name);

        match self.children.len() {
            0 => println!(""),
            _ => println!(":")
        };

        for child in self.children.iter() {
            child.print_recurse(indent + self.indet_length);
        }
    }
}

impl DsStoreParser {
    pub fn new() -> Self {
        Self {
            file_signature: vec![
                0x00, 0x00, 0x00, 0x01,
                0x42, 0x75, 0x64, 0x31,
            ],
            record_terminator: vec![
                0x76, 0x53, 0x72, 0x6e,
                0x6c, 0x6f, 0x6e, 0x67,
                0x00, 0x00, 0x00, 0x01,
            ],
            block_size: 0x04,
            root_offset_location: 0x08,
            root_offset_location_check: 0x10,
            index_padding: 0x100,
        }
    }

    pub fn parse(&self, file: &str) -> Result<DsStore, String> {
        let file = File::open(file).expect("Unable to open file".into());
        let mut reader = BufReader::new(file);
        let mut buf = Vec::<u8>::new();

        reader.read_to_end(&mut buf).expect("Failed to read file into buffer".into());

        if !self.confirm_signature(&buf) {
            return Err("Signature does not match a DS_Store file".into());
        }

        let root_offset = self.block_to_usize(&buf, self.root_offset_location)?
            + self.block_size;

        let root_offset_check = self.block_to_usize(&buf, self.root_offset_location_check)?
            + self.block_size;

        if root_offset != root_offset_check {
            return Err(
                format!(
                    "Root block offsets do not match: 0x{:x} != 0x{:x}",
                    root_offset, root_offset_check
                )
            );
        }

        let entry_count = self.block_to_usize(&buf, root_offset)?;
        let mut entry_indices = Vec::<usize>::new();

        for i in 0..entry_count {
            entry_indices.push(
                self.block_to_usize(
                    &buf,
                    root_offset + self.block_size + (self.block_size * (i + 1))
                )?
            );
        }

        let root_content_offset = root_offset +
            ((self.block_size * self.index_padding) % root_offset) +
            (2 * self.block_size);

        let root_id = self.block_to_usize(
            &buf,
            root_content_offset + (self.block_size * 2) + 1
        )?;

        let root_name: String = match str::from_utf8(&buf[
            root_content_offset + self.block_size + 1
            ..
            root_content_offset + (self.block_size * 2) + 1
        ]) {
            Ok(raw_name) => raw_name.into(),
            Err(_) => {
                return Err("Root node name contains illegal UTF-8 sequence".into());
            }
        };

        let (index_offset, _) = self.entry_index_to_entry_data(entry_indices[root_id]);
        let entry_id = self.block_to_usize(&buf, index_offset)?;
        let (entry_offset, _) = self.entry_index_to_entry_data(entry_indices[entry_id]);

        let mut root_node = DsStore {
            name: root_name,
            children: vec![],
            indet_length: 4,
        };

        let ds_store_tree = self.generate_ds_store_tree(
            &buf,
            entry_offset
        )?;

        for node in ds_store_tree {
            root_node.children.push(node);
        }

        Ok(root_node)
    }

    fn generate_ds_store_tree(
        &self,
        buf: &Vec<u8>,
        mut offset: usize
    ) -> Result<Vec<DsStore>, String> {
        let mut result = Vec::<DsStore>::new();
        let mode = self.block_to_usize(&buf, offset)?;

        if mode != 0 {
            panic!("Dev was too lazy for this.");
        }

        let record_count = self.block_to_usize(&buf, offset + self.block_size)?;

        for _ in 0..record_count {
            let record_size = self.block_to_usize(
                &buf,
                offset + (self.block_size * 2)
            )?;

            let record_utf16 = &buf[
                offset + (self.block_size * 3 )
                ..
                offset + (self.block_size * 3) + record_size * 2
            ];

            let utf16_packets = record_utf16
                .chunks(2)
                .map(|e| u16::from_be_bytes(e.try_into().unwrap()))
                .collect::<Vec<_>>();

            let record = String::from_utf16_lossy(&utf16_packets);
            result.push(
                DsStore {
                    name: record,
                    children: vec![],
                    indet_length: 4,
                }
            );

            let mut end_of_record = false;
            while !end_of_record {
                if buf.len() < offset + (self.block_size * 2) {
                    return Ok(result);
                }

                let pattern = &buf[
                    offset
                    ..
                    offset + (self.block_size * 2)
                ];

                end_of_record = true;
                for (a, b) in self.record_terminator.iter().zip(pattern) {
                    if a != b {
                        offset += 1;
                        end_of_record = false;
                        break;
                    }
                }
            }

            offset += self.block_size;
        }

        Ok(result)
    }

    pub fn confirm_signature(&self, buf: &Vec<u8>) -> bool {
        if buf.len() < self.file_signature.len() {
            println!("Input file is shorten then file signature");
            return false;
        }

        for (a, b) in self.file_signature.iter().zip(buf) {
            if a != b {
                println!(
                    "Failure during signature check: Expected byte 0x{:x}, got 0x{:x}",
                    a, b,
                );
                return false;
            }
        }

        true
    }

    fn entry_index_to_entry_data(&self, entry_index: usize) -> (usize, usize) {
        let offset = ((entry_index >> 0x5) << 0x5) + self.block_size;
        let size = 1 << (entry_index & 0x1f);
        (offset, size)
    }

    fn block_to_usize(&self, buf: &Vec<u8>, offset: usize) -> Result<usize, String> {
        if buf.len() < (offset + self.block_size) {
            return Err(
                format!(
                    "Failed to parse block at offset 0x{:x}. Offset out of range",
                    offset
                )
            );
        }

        let mut block: usize = 0x00000000;

        for i in 0..self.block_size {
            block ^= buf[offset + i] as usize;
            block <<= BYTE_SIZE;
        }

        block >>= BYTE_SIZE;
        Ok(block)
    }
}

fn main() {
    let args = Args::parse();

    let dss_parser = DsStoreParser::new();
    let ds_store = match dss_parser.parse(&args.file) {
        Ok(ds_store) => ds_store,
        Err(msg) => {
            eprintln!("ERROR: {}. Aborting.", msg);
            return;
        }
    };

    ds_store.print();
}
