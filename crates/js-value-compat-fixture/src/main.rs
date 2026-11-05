use std::io::{BufRead, Read, Write};
fn main() -> std::io::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let read = std::io::Read::by_ref(&mut input)
            .take((chat2local_js_value_compat_fixture::FRAME + 2) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > chat2local_js_value_compat_fixture::FRAME + 1 || !line.ends_with(b"\n") {
            return Err(std::io::Error::other(
                "Fixture frame limit or incomplete frame",
            ));
        }
        line.pop();
        output.write_all(&chat2local_js_value_compat_fixture::respond(&line))?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
