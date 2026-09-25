use std::io::{stdin, BufRead};
use string_analyze::analyze_with;
use string_analyze::rules::ALL_RULES;

fn main() {
    let input = stdin().lock();
    for line in input.lines() {
        if let Ok(s) = line {
            let r = analyze_with(&*s, &*ALL_RULES);
            if r.score() != 0 {
                println!("{:#}", r);
            }
        }
    }
}