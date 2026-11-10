use chat2local_oauth_compat_core::{Engine, FRAME_BYTES, MAX_WIRE_BYTES, dispatch};
use std::cell::RefCell;
#[derive(Default)]
struct Transport {
    engine: Engine,
    provider: chat2local_oauth_compat_core::provider::Engine,
    input: Vec<u8>,
    output: Vec<u8>,
    expected: Option<usize>,
    poisoned: bool,
}
thread_local! { static STATE: RefCell<Transport> = RefCell::new(Transport::default()); }
static mut INPUT: [u8; FRAME_BYTES] = [0; FRAME_BYTES];
static mut OUTPUT: [u8; FRAME_BYTES] = [0; FRAME_BYTES];
#[unsafe(no_mangle)]
pub extern "C" fn abi_version() -> u32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn frame_capacity() -> usize {
    FRAME_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn input_ptr() -> *mut u8 {
    std::ptr::addr_of_mut!(INPUT).cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn output_ptr() -> *const u8 {
    std::ptr::addr_of!(OUTPUT).cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn input_begin(length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.poisoned || state.expected.is_some() || length > MAX_WIRE_BYTES {
            state.poisoned = true;
            return 1;
        }
        state.input.clear();
        state.output.clear();
        state.expected = Some(length);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn input_append(length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.poisoned
            || length > FRAME_BYTES
            || state
                .expected
                .is_none_or(|expected| state.input.len() + length > expected)
        {
            state.poisoned = true;
            return 1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(std::ptr::addr_of!(INPUT).cast(), length) };
        state.input.extend_from_slice(bytes);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn command(length: usize) -> u32 {
    execute(length, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn provider_abi_version() -> u32 {
    2
}
#[unsafe(no_mangle)]
pub extern "C" fn provider_command(length: usize) -> u32 {
    execute(length, true)
}
fn execute(length: usize, provider: bool) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.poisoned || state.expected.take() != Some(length) || state.input.len() != length {
            state.poisoned = true;
            return 1;
        }
        let input = std::mem::take(&mut state.input);
        let result = if provider {
            chat2local_oauth_compat_core::provider::dispatch(&mut state.provider, &input)
        } else {
            dispatch(&mut state.engine, &input)
        };
        if let Some(output) = result {
            state.output = output;
            0
        } else {
            state.poisoned = true;
            1
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn output_len() -> usize {
    STATE.with(|state| state.borrow().output.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn output_read(offset: usize) -> usize {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.poisoned || offset > state.output.len() {
            state.poisoned = true;
            return 0;
        }
        let bytes =
            &state.output[offset..state.output.len().min(offset.saturating_add(FRAME_BYTES))];
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                std::ptr::addr_of_mut!(OUTPUT).cast(),
                bytes.len(),
            );
        }
        bytes.len()
    })
}
