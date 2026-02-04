use anyhow::bail;
use anyhow::Result;
use demikernel::runtime::types::demi_qresult_t;
use demikernel::QToken;
use demikernel::{
    runtime::queue::QDesc, runtime::types::demi_opcode_t, runtime::types::demi_sgarray_t, LibOS, LibOSName,
};
use std::{collections::HashSet, env, os::raw::c_int, slice};
use std::{net::SocketAddr, time::Duration};

// Константы для настройки сетевого стека
const TIMEOUT_SECONDS: Duration = Duration::from_secs(10);
const AF_INET: c_int = libc::AF_INET;
pub const SOCK_STREAM: i32 = libc::SOCK_STREAM;

pub struct TcpClient {
    libos: LibOS,
    remote_addr: SocketAddr,
    open_qds: HashSet<QDesc>,
}

impl TcpClient {
    pub fn new(libos: LibOS, remote_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            libos,
            remote_addr,
            open_qds: HashSet::<QDesc>::default(),
        })
    }

    /// Создает сокет и регистрирует его дескриптор
    fn create_and_register_socket(&mut self) -> Result<QDesc> {
        let qd: QDesc = self.libos.socket(AF_INET, SOCK_STREAM, 0)?;
        self.open_qds.insert(qd);
        Ok(qd)
    }

    /// Закрывает сокет и удаляет его из списка активных
    fn issue_close_and_deregister_qd(&mut self, qd: QDesc) -> Result<()> {
        if self.open_qds.contains(&qd) {
            self.libos.close(qd)?;
            self.open_qds.remove(&qd);
        }
        Ok(())
    }

    /// Выделяет память в куче LibOS (Zero-copy DMA память)
    fn make_sgarray(&mut self, payload: &[u8]) -> Result<demi_sgarray_t> {
        let sga = self.libos.sgaalloc(payload.len())?;
        let ptr = sga.segments[0].data_buf_ptr as *mut u8;
        let len = sga.segments[0].data_len_bytes as usize;

        let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
        slice.copy_from_slice(payload);

        Ok(sga)
    }

    /// Основной метод: Подключение -> Отправка данных -> Ожидание подтверждения
    pub fn connect_and_send(&mut self, message: &str) -> Result<()> {
        let qd = self.create_and_register_socket()?;

        // 1. TCP Connect
        println!("Установка соединения с {:?}...", self.remote_addr);
        let qt: QToken = self.libos.connect(qd, self.remote_addr)?;
        let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

        if qr.qr_opcode != demi_opcode_t::DEMI_OPC_CONNECT {
            bail!("Ошибка подключения: {:?}", qr.qr_ret);
        }
        println!("TCP Handshake завершен успешно.");

        // 2. Отправка Payload
        let payload = message.as_bytes();
        let sga = self.make_sgarray(payload)?;

        println!("Отправка данных: \"{}\" ({} байт)", message, payload.len());
        let qt: QToken = self.libos.push(qd, &sga)?;
        let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

        if qr.qr_opcode != demi_opcode_t::DEMI_OPC_PUSH {
            self.libos.sgafree(sga)?;
            bail!("Ошибка при PUSH (отправке): {:?}", qr.qr_ret);
        }

        // После успешного wait данные переданы сетевой карте, можно освобождать SGA
        self.libos.sgafree(sga)?;
        println!("Данные успешно переданы в сетевой стек.");

        // 3. Закрытие соединения
        self.issue_close_and_deregister_qd(qd)?;
        println!("Соединение закрыто.");

        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Использование: ./tcp_client <IP:PORT>");
        return Ok(());
    }

    // Парсим адрес назначения
    let remote_addr: SocketAddr = args[1].parse().expect("Неверный формат адреса");

    // Выбираем библиотечную ОС (по умолчанию Catnap для Linux или Catnip для DPDK/Mellanox)
    let libos_name = match LibOSName::from_env() {
        Ok(name) => name,
        Err(_) => LibOSName::Catnap, // Фолбэк на стандартные сокеты, если переменная не задана
    };

    let libos = LibOS::new(libos_name, None)?;
    let mut client = TcpClient::new(libos, remote_addr)?;

    // Запускаем процесс
    client.connect_and_send("Hello from Demikernel Mellanox Client!")?;

    Ok(())
}
