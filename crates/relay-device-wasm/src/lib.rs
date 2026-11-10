use chat2local_relay_device_core::{FRAME_BYTES, State, dispatch};
use std::cell::RefCell;
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
static mut INPUT: [u8; FRAME_BYTES] = [0; FRAME_BYTES];
static mut OUTPUT: [u8; FRAME_BYTES] = [0; FRAME_BYTES];
static mut OUTPUT_LEN: usize = 0;
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
pub extern "C" fn output_len() -> usize {
    unsafe { OUTPUT_LEN }
}
#[unsafe(no_mangle)]
pub extern "C" fn command(length: usize) -> u32 {
    unsafe {
        OUTPUT_LEN = 0;
    }
    if length > FRAME_BYTES {
        return 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(std::ptr::addr_of!(INPUT).cast(), length) };
    let response = STATE.with(|state| dispatch(&mut state.borrow_mut(), bytes));
    if let Some(response) = response {
        unsafe {
            std::ptr::copy_nonoverlapping(
                response.as_ptr(),
                std::ptr::addr_of_mut!(OUTPUT).cast(),
                response.len(),
            );
            OUTPUT_LEN = response.len();
        }
        0
    } else {
        1
    }
}
