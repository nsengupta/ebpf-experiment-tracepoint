#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes}, macros::tracepoint, programs::TracePointContext
};
use aya_log_ebpf::info;

const MAX_PATH: usize = 64;

#[tracepoint]
pub fn aya_tracepoint_echo_open(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint_echo_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_aya_tracepoint_echo_open(ctx: TracePointContext) -> Result<u32, i64> {

    let mut buf: [u8; MAX_PATH] = [0; MAX_PATH];

    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 16;
   if let Ok(filename_addr) = unsafe { ctx.read_at::<u64>(FILENAME_OFFSET) } {

    info!(&ctx, "tracepoint sys_enter_openat called filename addr obtained");
       // read the filename
        let filename = unsafe {
            core::str::from_utf8_unchecked(
                match bpf_probe_read_user_str_bytes(
                    filename_addr as *const u8,
                    &mut buf,
                ) {
                    Ok(_) =>  {
                        info!(&ctx, "tracepoint sys_enter_openat called buf_probe obtained");
                        &buf
                    },
                    Err(e)  => {
                        info!(&ctx, "tracepoint sys_enter_openat called buf_probe failed {}", e);
                        return Err(e);
                    }, 
                }
            )
        };
        
        info!(&ctx, "tracepoint sys_enter_openat called, filename  {}", filename);  
        
    }
   
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
