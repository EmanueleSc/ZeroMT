use csv::Writer;
use std::fs::File;

pub struct CsvUtils {
    csv_writer: Writer<File>,
}

impl CsvUtils {
    pub fn new(file_path: String, labels: Vec<String>) -> Self {
        let mut csv_writer: Writer<File> = Writer::from_path(file_path).unwrap();

        let _result = csv_writer.write_record(&labels);
        let _result = csv_writer.flush();
        CsvUtils { csv_writer }
    }

    pub fn write_content(&mut self, contents: Vec<String>) {
        contents
            .iter()
            .for_each(|s: &String| self.csv_writer.write_field(s).unwrap());
        self.csv_writer.flush().unwrap();
    }

    pub fn next_line(&mut self) {
        self.csv_writer.write_record(None::<&[u8]>).unwrap();
        self.csv_writer.flush().unwrap();
    }
}
