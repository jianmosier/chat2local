use super::{Document, Error, ErrorKind, JsString, Limits, Object, Value, ValueId};

#[derive(Clone, Copy)]
enum State {
    ArrayFirst,
    ArrayNext,
    ArrayComma,
    ObjectFirst,
    ObjectNext,
    ObjectComma,
}
struct Frame {
    id: ValueId,
    state: State,
}
struct Parser<'a> {
    input: &'a [u16],
    position: usize,
    limits: Limits,
}

pub(super) fn parse(input: &[u16], limits: Limits) -> Result<Document, Error> {
    let mut p = Parser {
        input,
        position: 0,
        limits,
    };
    if input.len() > limits.input_units || limits.nodes == 0 {
        return Err(p.error(ErrorKind::Limit));
    }
    let mut doc = Document::new()?;
    p.whitespace();
    let (root, frame) = p.value(&mut doc)?;
    doc.root = root;
    let mut stack = Vec::new();
    p.push(&mut stack, frame)?;
    while let Some(frame) = stack.last() {
        let (id, state) = (frame.id, frame.state);
        p.whitespace();
        match state {
            State::ArrayComma | State::ObjectComma => {
                let array = matches!(state, State::ArrayComma);
                if p.peek() == Some(if array { 93 } else { 125 }) {
                    p.position += 1;
                    stack.pop();
                } else {
                    p.expect(44)?;
                    stack.last_mut().unwrap().state = if array {
                        State::ArrayNext
                    } else {
                        State::ObjectNext
                    };
                }
            }
            State::ArrayFirst | State::ArrayNext => {
                if matches!(state, State::ArrayFirst) && p.peek() == Some(93) {
                    p.position += 1;
                    stack.pop();
                    continue;
                }
                let (value, child) = p.value(&mut doc)?;
                doc.push(id, value)?;
                stack.last_mut().unwrap().state = State::ArrayComma;
                p.push(&mut stack, child)?;
            }
            State::ObjectFirst | State::ObjectNext => {
                if matches!(state, State::ObjectFirst) && p.peek() == Some(125) {
                    p.position += 1;
                    stack.pop();
                    continue;
                }
                let key = p.string()?;
                p.whitespace();
                p.expect(58)?;
                p.whitespace();
                let (value, child) = p.value(&mut doc)?;
                doc.set_property(id, key, value)?;
                stack.last_mut().unwrap().state = State::ObjectComma;
                p.push(&mut stack, child)?;
            }
        }
    }
    p.whitespace();
    if p.position != input.len() {
        return Err(p.error(ErrorKind::Syntax));
    }
    Ok(doc)
}
impl Parser<'_> {
    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: self.position,
        }
    }
    fn peek(&self) -> Option<u16> {
        self.input.get(self.position).copied()
    }
    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(9 | 10 | 13 | 32)) {
            self.position += 1;
        }
    }
    fn expect(&mut self, unit: u16) -> Result<(), Error> {
        if self.peek() != Some(unit) {
            return Err(self.error(ErrorKind::Syntax));
        }
        self.position += 1;
        Ok(())
    }
    fn push(&self, stack: &mut Vec<Frame>, frame: Option<Frame>) -> Result<(), Error> {
        if let Some(frame) = frame {
            if stack.len() >= self.limits.depth {
                return Err(self.error(ErrorKind::Limit));
            }
            stack.push(frame);
        }
        Ok(())
    }
    fn literal(&mut self, word: &str) -> Result<(), Error> {
        for unit in word.bytes() {
            self.expect(u16::from(unit))?;
        }
        Ok(())
    }
    fn value(&mut self, doc: &mut Document) -> Result<(ValueId, Option<Frame>), Error> {
        let (value, state) = match self.peek() {
            Some(110) => {
                self.literal("null")?;
                (Value::Null, None)
            }
            Some(116) => {
                self.literal("true")?;
                (Value::Bool(true), None)
            }
            Some(102) => {
                self.literal("false")?;
                (Value::Bool(false), None)
            }
            Some(34) => (Value::String(self.string()?), None),
            Some(91) => {
                self.position += 1;
                (Value::Array(Vec::new()), Some(State::ArrayFirst))
            }
            Some(123) => {
                self.position += 1;
                (Value::Object(Object::default()), Some(State::ObjectFirst))
            }
            Some(45 | 48..=57) => (Value::Number(self.number()?), None),
            _ => return Err(self.error(ErrorKind::Syntax)),
        };
        let id = doc
            .add(value, self.limits.nodes)
            .map_err(|e| self.error(e.kind))?;
        Ok((id, state.map(|state| Frame { id, state })))
    }
    fn string(&mut self) -> Result<JsString, Error> {
        self.expect(34)?;
        let mut output = Vec::new();
        loop {
            let unit = self.peek().ok_or_else(|| self.error(ErrorKind::Syntax))?;
            self.position += 1;
            match unit {
                34 => return Ok(output),
                0..=31 => return Err(self.error(ErrorKind::Syntax)),
                92 => {
                    let escaped = self.peek().ok_or_else(|| self.error(ErrorKind::Syntax))?;
                    self.position += 1;
                    output.push(match escaped {
                        34 | 47 | 92 => escaped,
                        98 => 8,
                        102 => 12,
                        110 => 10,
                        114 => 13,
                        116 => 9,
                        117 => {
                            let mut value = 0u16;
                            for _ in 0..4 {
                                let digit = match self.peek() {
                                    Some(c @ 48..=57) => c - 48,
                                    Some(c @ 65..=70) => c - 65 + 10,
                                    Some(c @ 97..=102) => c - 97 + 10,
                                    _ => return Err(self.error(ErrorKind::Syntax)),
                                };
                                self.position += 1;
                                value = value * 16 + digit;
                            }
                            value
                        }
                        _ => return Err(self.error(ErrorKind::Syntax)),
                    });
                }
                _ => output.push(unit),
            }
        }
    }
    fn number(&mut self) -> Result<f64, Error> {
        let start = self.position;
        if self.peek() == Some(45) {
            self.position += 1;
        }
        match self.peek() {
            Some(48) => self.position += 1,
            Some(49..=57) => {
                while matches!(self.peek(), Some(48..=57)) {
                    self.position += 1;
                }
            }
            _ => return Err(self.error(ErrorKind::Syntax)),
        }
        if self.peek() == Some(46) {
            self.position += 1;
            if !matches!(self.peek(), Some(48..=57)) {
                return Err(self.error(ErrorKind::Syntax));
            }
            while matches!(self.peek(), Some(48..=57)) {
                self.position += 1;
            }
        }
        if matches!(self.peek(), Some(69 | 101)) {
            self.position += 1;
            if matches!(self.peek(), Some(43 | 45)) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(48..=57)) {
                return Err(self.error(ErrorKind::Syntax));
            }
            while matches!(self.peek(), Some(48..=57)) {
                self.position += 1;
            }
        }
        let number: String = self.input[start..self.position]
            .iter()
            .map(|n| char::from(*n as u8))
            .collect();
        number
            .parse::<f64>()
            .map_err(|_| self.error(ErrorKind::Syntax))
    }
}
