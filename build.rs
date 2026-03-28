use std::env;

fn main() {
    // 1. Пытаемся поймать путь к DPDK от нижней зависимости (dpdk_bindings)
    // Переменная называется DEP_DPDK_ROOT, потому что в биндингах links = "dpdk"
    // а в их build.rs написано println!("cargo:root=...");
    if let Ok(dpdk_root) = env::var("DEP_DPDK_ROOT") {
        // 2. Ретранслируем этот путь для нашего приложения (App)
        // Теперь в приложении будет доступна переменная DEP_DEMIKERNEL_ROOT
        println!("cargo:root={}", dpdk_root);

        // 3. Сообщаем линковщику самого демикренела, где искать либы
        println!("cargo:rustc-link-search=native={}", dpdk_root);

        // Прокидываем RPATH для тестов самого демикренела
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dpdk_root);

        // Полезный лог, который ты увидишь при cargo build -vv
        println!("cargo:warning=[DEMIKERNEL] Retransmitting DPDK_ROOT: {}", dpdk_root);
    } else {
        println!("cargo:warning=[DEMIKERNEL] Warning: DEP_DPDK_ROOT not found from bindings!");
    }

    // Инструкции для пересборки
    println!("cargo:rerun-if-env-changed=DEP_DPDK_ROOT");
    println!("cargo:rerun-if-changed=build.rs");
}
