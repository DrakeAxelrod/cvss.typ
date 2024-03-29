// use cvssrust::v3::V3Vector;
// use cvssrust::v2::V2Vector;
// use std::str::FromStr;
use cvssrust::CVSSScore;
use cvssrust::CVSS;
use cvss_tools::{calculate_score_v_4, calculate_severity_v_4};

// use wasm_minimal_protocol::{initiate_protocol, wasm_func};
use wasm_minimal_protocol::*;
initiate_protocol!();

// function to ve
#[wasm_func]
pub fn score(vector: &[u8]) -> Vec<u8> {
  let vec = std::str::from_utf8(vector).unwrap();
  // check if it starts with CVSS:4.0
  if vec.starts_with("CVSS:4.0") {
    let score: f32 = calculate_score_v_4(vec.to_string());
    score.to_string().as_bytes().to_vec()
  } else {
    match CVSS::parse(vec) {
        Ok(CVSS::V3(cvss)) => {
            let score = cvss.base_score().value();
            score.to_string().as_bytes().to_vec()
        },
        Ok(CVSS::V2(cvss)) => {
            let score = cvss.base_score().value();
            score.to_string().as_bytes().to_vec()
        },
        // _ => println!("Could not parse the CVSS vector"),
        _ => "Could not parse the CVSS vector".as_bytes().to_vec(),
    }
  }
}

#[wasm_func]
pub fn severity(vector: &[u8]) -> Vec<u8> {
  let vec = std::str::from_utf8(vector).unwrap();
  // check if it starts with CVSS:4.0
  if vec.starts_with("CVSS:4.0") {
    let score: f32 = calculate_score_v_4(vec.to_string());
    let severity = calculate_severity_v_4(score);
    severity.to_string().as_bytes().to_vec()
  } else {
    match CVSS::parse(vec) {
        Ok(CVSS::V3(cvss)) => {
            let severity = cvss.base_score().severity().to_string();
            severity.as_bytes().to_vec()
        },
        Ok(CVSS::V2(cvss)) => {
            let severity = cvss.base_score().severity().to_string();
            severity.as_bytes().to_vec()
        },
        // _ => println!("Could not parse the CVSS vector"),
        _ => "Could not parse the CVSS vector".as_bytes().to_vec(),
    }
  }
}
