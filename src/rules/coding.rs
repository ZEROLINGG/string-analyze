// string_analyze/src/rules/coding.rs
include!("./core/coding.rs");


#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
flag{5tgb8uik,0ol}
"666c61677b68656c6c6f","66 6c 61 67 7b","DEADBEEF0123456789",
ZmxhZ3toZWxsb19jdGZlcn0=
(+(+!+[]+[+[]]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+[+!+[]])[+!+[]] # JSfuck
++++++++[>>++>++++>++++++>++++++++>++++++++++>++++++++++++>++++++++++++++>++++++++++++++++>++++++++++++++++++>++++++++++++++++++++>++++++++++++++++++++++>++++++++++++++++++++++++>++++++++++++++++++++++++++>++++++++++++++++++++++++++++>++++++++++++++++++++++++++++++<<<<<<<<<<<<<<<<-]>>>>>>------.+++++++++.>++++++.>+++++.<---.++++++++. # Brainfuck
..--- ..--- ..--- ..--- ..--- .---- .---- .- ...
佛曰：楞皤耶诃摩啰咩参墀苏喝穆伊佛阿楞沙卢咩羯伽迦俱佛埵伽埵那咩参呼提陀数豆怛萨啰墀俱写夜吉罚吉陀迦提穆苏菩俱尼娑
楞皤耶诃摩啰咩参墀苏喝穆伊佛阿楞沙卢咩羯伽迦俱佛埵伽埵那咩参呼提陀数豆怛萨啰墀俱写夜吉罚吉陀迦提穆苏菩俱尼娑
~呜嗷呜呜呜啊~呜啊嗷啊呜啊啊嗷呜~嗷~呜~啊呜呜嗷嗷啊
Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook. Ook.  Ook! Ook.

"#;
        for line in input.lines() {
            println!("{}", analyze_with(
                line,
                &get_rules(|m, _| module_path!().split("::tests").any(|s| s == m)),
            ))
        }
        let input  = String::from_utf8(hex::decode("e99bb6e5aebde5ad97e7aca6e280ace2808ce280acefbbbfefbbbfefbbbfe2808defbbbf556e69636f6465e99a90e58699e69cafe99ba8e88b81e2808de2808de2808defbbbfe2808ce280ace280ace2808ce2808de280ace280acefbbbfe2808de280ace2808de2808ce2808de2808de280ace2808de2808ce2808ce2808de2808ce280ace2808cefbbbfefbbbfe280ace2808de2808cefbbbfe2808de2808de2808ce2808de2808de280ace2808de2808d0ae280ace2808de2808defbbbfe2808ce2808ce2808ce2808ce280ace2808ce280ace2808de280ace2808ce2808ce2808de280ace2808de2808de280ace280ace2808de2808ce2808ce280ace2808ce2808de2808defbbbfe2808cefbbbfefbbbfe2808defbbbfe2808de280ace280ace2808ce2808de2808ce2808de280ace2808de2808de280ace2808ce2808defbbbfe2808de2808de280acefbbbfe2808de2808de2808defbbbf0a").unwrap()).unwrap();
        println!("{}", analyze_with(
            &*input,
            &get_rules(|m, _| module_path!().split("::tests").any(|s| s == m)),
        ))
    }
}
