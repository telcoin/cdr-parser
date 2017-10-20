extern crate cdr_parser;
extern crate dotenv;
extern crate serde_json;
extern crate walkdir;

use std::env;
use std::fs::File;
use std::io::Read;

use dotenv::dotenv;
use walkdir::WalkDir;

#[test]
fn it_works() {
    dotenv().ok();
    for test in WalkDir::new(env::var("CDR_TEST_DIR").unwrap())
                        .min_depth(1)
                        .into_iter()
                        .filter_map(Result::ok)
                        .filter(|e| e.path().extension().map(|e| e == "dat").unwrap_or(false)) {
        let mut file = File::open(test.path()).unwrap();
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();

        let res = cdr_parser::huawei::msc::parse(buffer.as_slice());
        assert!(res.is_done());
        let cdr = res.to_result().unwrap();
        let json = serde_json::to_string(&cdr).unwrap();

        let mut file = File::open(test.path().with_extension("expect")).unwrap();
        let mut json_expect = String::new();
        file.read_to_string(&mut json_expect).unwrap();

        assert_eq!(json, json_expect);
    }
}
