use std::io::{BufRead, stdin};
use string_analyze::analyze_with;
use string_analyze::rules::ALL_RULES;

fn main() {
    let input = stdin().lock();
    for s in input.lines().map_while(Result::ok) {
        let r = analyze_with(&s, &ALL_RULES);
        if r.score() != 0 {
            println!("{:#}", r);
        }
    }
}
