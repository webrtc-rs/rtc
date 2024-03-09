use super::*;
use shared::error::Result;

#[test]
fn test_random_generator_collision() -> Result<()> {
    let test_cases = vec![
        (
            "CandidateID",
            0, /*||-> String {
                   generate_cand_id()
               },*/
        ),
        (
            "PWD", 1, /*||-> String {
                  generate_pwd()
              },*/
        ),
        (
            "Ufrag", 2, /*|| ->String {
                  generate_ufrag()
              },*/
        ),
    ];

    const N: usize = 10;
    const ITERATION: usize = 10;

    for (name, test_case) in test_cases {
        for _ in 0..ITERATION {
            let mut rs = vec![];

            for _ in 0..N {
                let s = if test_case == 0 {
                    generate_cand_id()
                } else if test_case == 1 {
                    generate_pwd()
                } else {
                    generate_ufrag()
                };

                rs.push(s);
            }

            assert_eq!(rs.len(), N, "{name} Failed to generate randoms");

            for i in 0..N {
                for j in i + 1..N {
                    assert_ne!(
                        rs[i], rs[j],
                        "{}: generateRandString caused collision: {} == {}",
                        name, rs[i], rs[j],
                    );
                }
            }
        }
    }

    Ok(())
}
