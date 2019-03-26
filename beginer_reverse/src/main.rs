//
// >>> [((int(ord(s)) << 2) ^ 42) for s in "INS{y0ur_a_r3a1_h4rdc0r3_r3v3rs3r}"]
// [270, 274, 358, 454, 462, 234, 510, 482, 342, 430, 342, 482, 230, 430, 238, 342, 394, 250, 482, 442, 422, 234, 482, 230, 342, 482, 230, 498, 230, 482, 486, 230, 482, 478]
//

use std::io::{self};

#[derive(Debug)]
struct Input<'a> {
    data: &'a str,
}

const LIFE: i32 = 42;

impl<'a> Input<'a> {
    fn new(buf: &'a str) -> Self {
        return Input {
            data: buf,
        }
    }
    fn check_valid_password(self, rf: &Vec<i32>) -> Self {
        let mut tmp: Vec<i32> = Vec::new();
        for c in self.data.bytes() {
            tmp.push(c as i32);
        }
        tmp.iter().for_each(
            |&v| {
                if v < 0x20 || v > 0x7e {
                    panic!("an error occured");
                }
            }
        );
        let matching = tmp.iter()
                          .zip( rf.iter()).filter(|&(a, b)| {
                            *a == ((*b ^ LIFE) >> 2)
                          }).count();
        if matching == rf.len() {
            println!("Submit this and get you'r points!");
        }
        self
    }
}

fn main() {
    let real_flag: Vec<_> = vec![
        270, 274, 358, 454, 462, 234, 510,
        482, 342, 430, 342, 482, 230, 430,
        238, 342, 394, 250, 482, 442, 422,
        234, 482, 230, 342, 482, 230, 498,
        230, 482, 486, 230, 482, 478
    ];

    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input)
               .expect("Error reading input");

    // remove the '\n' char
    user_input.pop();
    Input::new(&user_input).check_valid_password(&real_flag);
}
