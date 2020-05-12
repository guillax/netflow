pub fn read_unaligned_unchecked<'a, T>(data: &'a [u8]) -> T {
    let ptr = data.as_ptr() as *const T;
    unsafe { ptr.read_unaligned() }
}
