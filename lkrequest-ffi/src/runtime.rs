use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

pub fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("lkrequest-ffi")
            .build()
            .expect("failed to create lkrequest-ffi runtime")
    })
}
