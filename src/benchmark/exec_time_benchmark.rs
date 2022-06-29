use ark_serialize::CanonicalSerialize;
use csv::Writer;
use std::error::Error;
use std::fs::File;
use std::time::{Duration, Instant};

pub struct ExecTimeBenchmark {
    csv_writer: Writer<File>,
}

impl ExecTimeBenchmark {
    pub fn new(file_path: String, title: String, mut labels: Vec<String>) -> Self {
        let mut csv_writer: Writer<File> = Writer::from_path(file_path).unwrap();
        let mut first_line: Vec<String> = [title].to_vec();
        first_line.append(&mut labels);

        csv_writer.write_record(&first_line);
        csv_writer.flush();
        ExecTimeBenchmark { csv_writer }
    }

    pub fn bench_function(
        &mut self,
        has_title: bool,
        title_repetitions: String,
        function: &mut dyn FnMut() -> Vec<String>,
    ) {
        if has_title {
            self.csv_writer
                .write_field(format!("{}", title_repetitions))
                .unwrap();
        }

        let start = Instant::now();
        let results: Vec<String> = function();
        let duration: Duration = start.elapsed();

        self.csv_writer
            .write_field(duration.as_millis().to_string())
            .unwrap();

        results
            .iter()
            .for_each(|s: &String| self.csv_writer.write_field(s).unwrap());

        self.csv_writer.flush().unwrap();
    }

    pub fn next_line(&mut self) {
        self.csv_writer.write_record(None::<&[u8]>).unwrap();
        self.csv_writer.flush().unwrap();
    }
}
