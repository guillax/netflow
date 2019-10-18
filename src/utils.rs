
pub fn read_unaligned<'a, T>(data: &'a [u8]) -> T {
  assert!(data.len() >= std::mem::size_of::<T>());
  let ptr = data.as_ptr() as *const T;
  unsafe { ptr.read_unaligned() }
}