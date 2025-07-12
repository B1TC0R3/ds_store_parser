# ds_store_parser

Rudimentary DS_Store file name parser. Only supports mode 0.

Currently can figure out file names from a DS_Store file (something you can do by just looking
at a hex dump very easily) through actually attempting to parse the binary format.

There are multiple severe issues with this tool at the moment:

- It only checks the first entry index in the first place.
- There is no recursion. If a filename is stored in a directory, that structure will not be displayed in the output.
- The tool only supports index mode 0. Currently it just panics when it encounters mode 1 instead.

There is a statically build version in the release section if you don't want to build the project.

## Usage

```bash
./ds_store_parser --file <filename>
```

## Building

```bash
git clone https://github.com/B1TC0R3/ds_store_parser.git
cd ds_store_parser
cargo build --release
cp target/release/ds_store_parser .
```
