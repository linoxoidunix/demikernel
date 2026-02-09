// use anyhow::bail;
// use anyhow::Result;
// use demikernel::runtime::types::demi_qresult_t;
// use demikernel::QToken;
// use demikernel::{
//     runtime::queue::QDesc, runtime::types::demi_opcode_t, runtime::types::demi_sgarray_t, LibOS, LibOSName,
// };
// use std::{collections::HashSet, os::raw::c_int};
// use std::{net::SocketAddr, time::Duration};

// // Константы для настройки сетевого стека
// const TIMEOUT_SECONDS: Duration = Duration::from_secs(10);
// const AF_INET: c_int = libc::AF_INET;
// pub const SOCK_STREAM: i32 = libc::SOCK_STREAM;

// pub struct TcpClient {
//     pub libos: LibOS,
//     remote_addr: SocketAddr,
//     open_qds: HashSet<QDesc>,
// }

// impl TcpClient {
//     pub fn new(libos: LibOS, remote_addr: SocketAddr) -> Result<Self> {
//         Ok(Self {
//             libos,
//             remote_addr,
//             open_qds: HashSet::<QDesc>::default(),
//         })
//     }

//     /// Создает сокет и регистрирует его дескриптор
//     fn create_and_register_socket(&mut self) -> Result<QDesc> {
//         let qd: QDesc = self.libos.socket(AF_INET, SOCK_STREAM, 0)?;
//         self.open_qds.insert(qd);
//         Ok(qd)
//     }

//     /// Закрывает сокет и удаляет его из списка активных
//     fn issue_close_and_deregister_qd(&mut self, qd: QDesc) -> Result<()> {
//         if self.open_qds.contains(&qd) {
//             self.libos.close(qd)?;
//             self.open_qds.remove(&qd);
//         }
//         Ok(())
//     }

//     /// Выделяет память в куче LibOS (Zero-copy DMA память)
//     /// Выделяет память в куче LibOS (Zero-copy DMA память) и копирует payload
//     fn make_sgarray(&mut self, payload: &[u8]) -> Result<demi_sgarray_t> {
//         println!("try allocate sga array for payload...");
//         let sga = self.libos.sgaalloc(payload.len())?;
//         let num_segments = sga.num_segments;
//         println!("allocate sga array for payload complete. Segments: {}", num_segments);

//         let mut offset = 0;

//         // Проходим по всем сегментам, которые выделил sgaalloc
//         for i in 0..num_segments as usize {
//             let seg_ptr = sga.segments[i].data_buf_ptr as *mut u8;
//             let seg_len = sga.segments[i].data_len_bytes as usize;

//             if seg_ptr.is_null() {
//                 // На всякий случай проверяем указатель
//                 anyhow::bail!("SGA segment {} has a null pointer", i);
//             }

//             // Создаем слайс для текущего сегмента
//             let dest_slice = unsafe { std::slice::from_raw_parts_mut(seg_ptr, seg_len) };

//             // Определяем, сколько байт из payload нужно скопировать в этот сегмент
//             let remaining_payload = payload.len() - offset;
//             let bytes_to_copy = std::cmp::min(seg_len, remaining_payload);

//             if bytes_to_copy > 0 {
//                 let src_slice = &payload[offset..(offset + bytes_to_copy)];
//                 dest_slice[..bytes_to_copy].copy_from_slice(src_slice);
//                 offset += bytes_to_copy;
//             }

//             // Если мы уже скопировали весь payload, можно выходить
//             if offset >= payload.len() {
//                 break;
//             }
//         }

//         // Проверка на случай, если sgaalloc выделил меньше памяти, чем мы просили
//         if offset < payload.len() {
//             // Освобождаем память, если что-то пошло не так
//             let _ = self.libos.sgafree(sga);
//             anyhow::bail!("SGA too small: copied {}/{} bytes", offset, payload.len());
//         }

//         Ok(sga)
//     }

//     /// Основной метод: Подключение -> Отправка данных -> Ожидание подтверждения
//     pub fn connect_and_send(&mut self, message: &str) -> Result<()> {
//         let qd = self.create_and_register_socket()?;

//         // 1. TCP Connect
//         println!("Установка соединения с {:?}...", self.remote_addr);
//         let qt: QToken = self.libos.connect(qd, self.remote_addr)?;
//         let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

//         if qr.qr_opcode != demi_opcode_t::DEMI_OPC_CONNECT {
//             bail!("Ошибка подключения: {:?}", qr.qr_ret);
//         }
//         println!("TCP Handshake завершен успешно.");

//         // 2. Отправка Payload
//         let payload = message.as_bytes();
//         let sga = self.make_sgarray(payload)?;

//         println!("Отправка данных: \"{}\" ({} байт)", message, payload.len());
//         let qt: QToken = self.libos.push(qd, &sga)?;
//         let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

//         if qr.qr_opcode != demi_opcode_t::DEMI_OPC_PUSH {
//             self.libos.sgafree(sga)?;
//             bail!("Ошибка при PUSH (отправке): {:?}", qr.qr_ret);
//         }

//         // После успешного wait данные переданы сетевой карте, можно освобождать SGA
//         self.libos.sgafree(sga)?;
//         println!("Данные успешно переданы в сетевой стек.");

//         // 3. Закрытие соединения
//         self.issue_close_and_deregister_qd(qd)?;
//         println!("Соединение закрыто.");

//         Ok(())
//     }

//     /// 1. Отдельный метод для установки соединения
//     pub fn connect(&mut self) -> Result<QDesc> {
//         let qd = self.create_and_register_socket()?;

//         println!("Установка соединения с {:?}...", self.remote_addr);
//         let qt: QToken = self.libos.connect(qd, self.remote_addr)?;
//         let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

//         if qr.qr_opcode != demi_opcode_t::DEMI_OPC_CONNECT {
//             self.issue_close_and_deregister_qd(qd).ok(); // Пытаемся закрыть при ошибке
//             bail!("Ошибка подключения: {:?}", qr.qr_ret);
//         }

//         println!("TCP Handshake завершен. Соединение ESTABLISHED (QD: {:?})", qd);
//         Ok(qd)
//     }

//     pub fn send<T: AsRef<[u8]>>(&mut self, qd: QDesc, data: T) -> Result<()> {
//         // data.as_ref() превращает любой входной тип в &[u8]
//         let payload = data.as_ref();

//         let sga = self.make_sgarray(payload)?;

//         // Отправка через Demikernel LibOS
//         let qt: QToken = self.libos.push(qd, &sga)?;
//         let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

//         // Гарантированное освобождение DMA-памяти
//         self.libos.sgafree(sga)?;

//         if qr.qr_opcode != demi_opcode_t::DEMI_OPC_PUSH {
//             bail!("Ошибка при PUSH: {:?}", qr.qr_ret);
//         }

//         Ok(())
//     }

//     /// 3. Отдельный метод для закрытия
//     pub fn close(&mut self, qd: QDesc) -> Result<()> {
//         println!("Инициируем закрытие соединения (QD: {:?})...", qd);
//         self.issue_close_and_deregister_qd(qd)?;
//         Ok(())
//     }

//     /// Принимает данные из сокета
//     pub fn receive(&mut self, qd: QDesc) -> Result<Vec<u8>> {
//         // 1. Создаем операцию извлечения данных
//         let qt: QToken = self.libos.pop(qd, None)?;

//         // 2. Ждем прихода пакета
//         let qr: demi_qresult_t = self.libos.wait(qt, Some(TIMEOUT_SECONDS))?;

//         if qr.qr_opcode != demi_opcode_t::DEMI_OPC_POP {
//             bail!("Ошибка при получении данных (POP): {:?}", qr.qr_ret);
//         }

//         // 3. Достаем данные из структуры sgarray
//         let sga = unsafe { qr.qr_value.sga };
//         let mut data = Vec::new();

//         for i in 0..sga.num_segments as usize {
//             let ptr = sga.segments[i].data_buf_ptr as *mut u8;
//             let len = sga.segments[i].data_len_bytes as usize;
//             let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
//             data.extend_from_slice(slice);
//         }

//         // 4. ОСВОБОЖДАЕМ ПАМЯТЬ, выделенную стеком под входящий пакет
//         self.libos.sgafree(sga)?;

//         Ok(data)
//     }
// }

// use std::{env};
// fn main() -> Result<()> {
//     let args: Vec<String> = env::args().collect();
//     if args.len() < 2 {
//         println!("Использование: ./tcp_client <IP:PORT>");
//         return Ok(());
//     }

//     // Парсим адрес назначения
//     let remote_addr: SocketAddr = args[1].parse().expect("Неверный формат адреса");

//     // Выбираем библиотечную ОС (по умолчанию Catnap для Linux или Catnip для DPDK/Mellanox)
//     let libos_name = match LibOSName::from_env() {
//         Ok(name) => name,
//         Err(_) => LibOSName::Catnip, // Фолбэк на стандартные сокеты, если переменная не задана
//     };

//     let libos = LibOS::new(libos_name, None)?;
//     let mut client = TcpClient::new(libos, remote_addr)?;

//     // 1. Подключаемся ОДИН раз
//     let qd = client.connect()?;

//     // 2. Отправляем данные МНОГО раз в том же соединении
//     for _i in 1..=5 {
//         //let msg = format!("Message number {} from Mellanox", i);
//         let big_data: Vec<u8> = vec![0x41; 3000];
//         client.send(qd, &big_data)?;

//         // Небольшая пауза, чтобы в Wireshark пакеты не склеились (опционально)
//         std::thread::sleep(std::time::Duration::from_millis(500));
//     }

//     // 3. Закрываем ОДИН раз
//     client.close(qd)?;

//     Ok(())
// }

use anyhow::{bail, Result};
use demikernel::{
    runtime::types::{demi_opcode_t, demi_sgarray_t},
    LibOS, QDesc, QToken,
};
use std::{collections::HashMap, net::SocketAddr, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Контейнер для входящих данных без копирования.
pub struct ReceivedMessage<'a> {
    libos: &'a mut LibOS,
    sga: demi_sgarray_t,
}

impl<'a> ReceivedMessage<'a> {
    pub fn segments(&self) -> Vec<&[u8]> {
        let mut views = Vec::new();
        for i in 0..self.sga.num_segments as usize {
            let seg = self.sga.segments[i];
            let slice =
                unsafe { std::slice::from_raw_parts(seg.data_buf_ptr as *const u8, seg.data_len_bytes as usize) };
            views.push(slice);
        }
        views
    }
}

impl<'a> Drop for ReceivedMessage<'a> {
    fn drop(&mut self) {
        let _ = self.libos.sgafree(self.sga);
    }
}

pub struct FastTcpClient {
    pub libos: LibOS,
    remote_addr: SocketAddr,
    // Все активные токены для wait_any
    tokens: Vec<QToken>,
    // Мапа для связи токена PUSH с его буфером в памяти Hugepages
    pending_pushes: HashMap<QToken, demi_sgarray_t>,
}

impl FastTcpClient {
    pub fn new(libos: LibOS, remote_addr: SocketAddr) -> Self {
        Self {
            libos,
            remote_addr,
            tokens: Vec::new(),
            pending_pushes: HashMap::new(),
        }
    }

    pub fn connect(&mut self) -> Result<QDesc> {
        let qd = self.libos.socket(libc::AF_INET, libc::SOCK_STREAM, 0)?;
        let qt = self.libos.connect(qd, self.remote_addr)?;
        let qr = self.libos.wait(qt, Some(TIMEOUT))?;

        if qr.qr_opcode != demi_opcode_t::DEMI_OPC_CONNECT {
            bail!("Connect failed: {:?}", qr.qr_ret);
        }
        Ok(qd)
    }

    /// Асинхронная отправка: аллоцируем SGA и сохраняем его до завершения операции
    pub fn push_async(&mut self, qd: QDesc, data: &[u8]) -> Result<()> {
        let sga = self.make_sgarray(data)?;
        let qt = self.libos.push(qd, &sga)?;

        self.tokens.push(qt);
        // Сохраняем SGA, чтобы освободить его позже в poll()
        self.pending_pushes.insert(qt, sga);

        Ok(())
    }

    pub fn pop_async(&mut self, qd: QDesc) -> Result<()> {
        let qt = self.libos.pop(qd, None)?;
        self.tokens.push(qt);
        Ok(())
    }

    /// Главный метод: опрашивает готовность и САМ чистит память после PUSH
    pub fn poll(&mut self) -> Result<Option<ReceivedMessage<'_>>> {
        if self.tokens.is_empty() {
            return Ok(None);
        }

        // Ждем готовности хотя бы одного события
        let (index, qr) = self.libos.wait_any(&self.tokens, None)?;
        let qt = self.tokens.remove(index);

        match qr.qr_opcode {
            demi_opcode_t::DEMI_OPC_POP => {
                let sga = unsafe { qr.qr_value.sga };
                Ok(Some(ReceivedMessage {
                    libos: &mut self.libos,
                    sga,
                }))
            },
            demi_opcode_t::DEMI_OPC_PUSH => {
                // Пакет успешно передан сетевой карте
                // Теперь мы МОЖЕМ и ДОЛЖНЫ освободить SGA буфер
                if let Some(sga) = self.pending_pushes.remove(&qt) {
                    self.libos.sgafree(sga)?;
                }
                Ok(None)
            },
            demi_opcode_t::DEMI_OPC_FAILED => {
                // Если операция провалилась, память тоже нужно вернуть
                if let Some(sga) = self.pending_pushes.remove(&qt) {
                    let _ = self.libos.sgafree(sga);
                }
                bail!("Operation failed for token {:?}", qt)
            },
            _ => Ok(None),
        }
    }

    fn make_sgarray(&mut self, payload: &[u8]) -> Result<demi_sgarray_t> {
        let sga = self.libos.sgaalloc(payload.len())?;
        let mut offset = 0;
        for i in 0..sga.num_segments as usize {
            let seg = &sga.segments[i];
            let dest =
                unsafe { std::slice::from_raw_parts_mut(seg.data_buf_ptr as *mut u8, seg.data_len_bytes as usize) };
            let to_copy = std::cmp::min(dest.len(), payload.len() - offset);
            dest[..to_copy].copy_from_slice(&payload[offset..offset + to_copy]);
            offset += to_copy;
        }
        Ok(sga)
    }

    pub fn send_and_wait(&mut self, qd: QDesc, data: &[u8]) -> Result<()> {
        // 1. Выделяем память (SGA)
        let sga = self.make_sgarray(data)?;

        // 2. Инициируем отправку
        // Важно: LibOS клонирует структуру sga, но не сами данные в Hugepages.
        // Поэтому данные должны жить, пока wait не вернет управление.
        let qt: QToken = self.libos.push(qd, &sga)?;

        // 3. Ждем подтверждения от сетевой карты, что данные ушли
        let qr = self.libos.wait(qt, Some(TIMEOUT))?;

        // 4. ОСВОБОЖДАЕМ ПАМЯТЬ сразу после подтверждения
        // Теперь мы точно знаем, что Mellanox прочитал данные из RAM
        self.libos.sgafree(sga)?;

        // 5. Проверяем, что отправка прошла успешно
        if qr.qr_opcode != demi_opcode_t::DEMI_OPC_PUSH {
            bail!("Ошибка при отправке: {:?}", qr.qr_ret);
        }

        Ok(())
    }

    /// Ждет один пакет от сетевой карты и возвращает Zero-copy сообщение.
    pub fn receive_blocking(&mut self, qd: QDesc) -> Result<ReceivedMessage<'_>> {
        // 1. Инициируем операцию POP (извлечение из очереди сетевой карты)
        // None в pop означает, что мы берем любой доступный объем данных
        let qt: QToken = self.libos.pop(qd, None)?;

        // 2. Блокируем поток до прихода данных или таймаута
        let qr = self.libos.wait(qt, Some(TIMEOUT))?;

        // 3. Проверяем результат
        match qr.qr_opcode {
            demi_opcode_t::DEMI_OPC_POP => {
                let sga = unsafe { qr.qr_value.sga };

                // Проверка на закрытие соединения со стороны сервера
                if sga.num_segments == 0 || (sga.num_segments > 0 && sga.segments[0].data_len_bytes == 0) {
                    let _ = self.libos.sgafree(sga);
                    bail!("Connection closed by remote peer");
                }

                // Возвращаем обертку, которая сама вызовет sgafree при Drop
                Ok(ReceivedMessage {
                    libos: &mut self.libos,
                    sga,
                })
            },
            demi_opcode_t::DEMI_OPC_FAILED => {
                bail!("POP operation failed: error code {:?}", qr.qr_ret);
            },
            _ => {
                bail!("Unexpected opcode received: {:?}", qr.qr_opcode);
            },
        }
    }
}

use demikernel::LibOSName;
use std::env;
// fn main() -> Result<()> {
//      let args: Vec<String> = env::args().collect();
//     if args.len() < 2 {
//         println!("Использование: ./tcp_client <IP:PORT>");
//         return Ok(());
//     }

//     // Парсим адрес назначения
//     let remote_addr: SocketAddr = args[1].parse().expect("Неверный формат адреса");

//     let libos = LibOS::new(LibOSName::Catnip, None)?;
//     let mut client = FastTcpClient::new(libos, remote_addr);

//     let qd = client.connect()?;

//     // 1. Сразу закидываем "запрос" на чтение (чтобы карта была готова принять)
//     client.pop_async(qd)?;

//     // 2. Отправляем пачку данных (не дожидаясь ответа)
//     client.push_async(qd, &[0x41; 3000])?;
//     client.push_async(qd, &[0x42; 3000])?;

//     // 3. Цикл обработки
//     loop {
//         if let Some(msg) = client.poll()? {
//             // РАБОТАЕМ БЕЗ КОПИРОВАНИЯ
//             for segment in msg.segments() {
//                 println!("Получен сегмент длиной: {}", segment.len());
//                 // Обрабатываем segment как &[u8]
//             }
//             // Как только цикл закончится, msg удалится и вызовется sgafree
//             break;
//         }
//     }

//     Ok(())
// }

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Использование: ./tcp_client <IP:PORT>");
        return Ok(());
    }

    // Парсим адрес назначения
    let remote_addr: SocketAddr = args[1].parse().expect("Неверный формат адреса");

    let libos = LibOS::new(LibOSName::Catnip, None)?;
    let mut client = FastTcpClient::new(libos, remote_addr);
    let qd = client.connect()?;

    let data = vec![0x41; 30000];

    for i in 0..2 {
        println!("Отправка пакета №{}", i);

        // Отправляем и ждем освобождения ресурсов
        client.send_and_wait(qd, &data)?;

        // В этой точке память sga уже гарантированно свободна,
        // и мы можем начинать следующую итерацию без риска утечки.
    }

    client.libos.close(qd)?;
    Ok(())
}
