// src/tcp_server/connection.rs
use crate::{
    runtime::types::{demi_opcode_t, demi_qresult_t, demi_sgarray_t},
    LibOS, QDesc, QToken,
};
use anyhow::{bail, Result};
use std::{collections::HashSet, net::SocketAddr, os::raw::c_int, time::Duration};

// Константы
const AF_INET: c_int = libc::AF_INET;
pub const SOCK_STREAM: i32 = libc::SOCK_STREAM;

pub struct TcpServer {
    pub libos: LibOS,
    local_addr: SocketAddr,
    pub listening_sockqd: QDesc,
    pub connected_clients: HashSet<QDesc>,
    pub pending_qtokens: Vec<QToken>,
}

impl TcpServer {
    /// Создание сервера: socket + bind + listen
    pub fn new(mut libos: LibOS, local_addr: SocketAddr) -> Result<Self> {
        let listening_sockqd: QDesc = libos.socket(AF_INET, SOCK_STREAM, 0)?;

        if let Err(e) = libos.bind(listening_sockqd, local_addr) {
            libos.close(listening_sockqd)?;
            bail!("bind failed: {:?}", e);
        }

        if let Err(e) = libos.listen(listening_sockqd, 1024) {
            libos.close(listening_sockqd)?;
            bail!("listen failed: {:?}", e);
        }

        Ok(Self {
            libos,
            local_addr,
            listening_sockqd,
            connected_clients: HashSet::default(),
            pending_qtokens: Vec::default(),
        })
    }

    /// Выделение DMA-памяти (совместимо с TcpClient)
    pub fn make_sgarray(&mut self, payload: &[u8]) -> Result<demi_sgarray_t> {
        let mut sga = self.libos.sgaalloc(payload.len())?;
        if sga.num_segments == 0 {
            bail!("sgaalloc returned empty sgarray");
        }

        let mut offset = 0;
        for i in 0..sga.num_segments as usize {
            let segment = &mut sga.segments[i];
            let seg_len = segment.data_len_bytes as usize;

            // Сколько байт копируем в текущий сегмент
            let to_copy = std::cmp::min(seg_len, payload.len() - offset);
            if to_copy == 0 {
                break;
            }

            let ptr = segment.data_buf_ptr as *mut u8;
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, to_copy) };
            slice.copy_from_slice(&payload[offset..offset + to_copy]);

            offset += to_copy;
        }

        if offset != payload.len() {
            bail!(
                "Not all payload bytes copied to sgarray: copied={}, total={}",
                offset,
                payload.len()
            );
        }

        Ok(sga)
    }

    // pub fn make_sgarray(&mut self, payload: &[u8]) -> Result<demi_sgarray_t> {
    //     let sga = self.libos.sgaalloc(payload.len())?;

    //     // Проверяем, что у нас есть хотя бы один сегмент и он достаточного размера
    //     if sga.num_segments == 0 || (sga.segments[0].data_len_bytes as usize) < payload.len() {
    //         // Если условие не выполняется, освобождаем память и выходим с ошибкой
    //         self.libos.sgafree(sga).ok();
    //         bail!("sgaalloc returned insufficient segments or empty sgarray");
    //     }

    //     let ptr = sga.segments[0].data_buf_ptr as *mut u8;
    //     unsafe {
    //         // Копируем данные напрямую в первый сегмент
    //         std::ptr::copy_nonoverlapping(payload.as_ptr(), ptr, payload.len());
    //     }

    //     Ok(sga)
    //}

    /// ==================== ISSUE методы (отправка операций) ====================

    pub fn issue_accept(&mut self) -> Result<()> {
        let qt: QToken = self.libos.accept(self.listening_sockqd)?;
        self.pending_qtokens.push(qt);
        Ok(())
    }

    pub fn issue_pop(&mut self, qd: QDesc) -> Result<QToken> {
        // Вызываем pop и получаем токен операции
        let qt: QToken = self.libos.pop(qd, None)?;

        // log::trace!("[TCP] Issue POP for qd={:?}, qt={:?}", qd, qt);

        // Возвращаем токен, чтобы WssServer мог положить его в ConnectionState
        Ok(qt)
    }

    pub fn issue_push(&mut self, qd: QDesc, sga: &demi_sgarray_t) -> Result<()> {
        let qt: QToken = self.libos.push(qd, sga)?;
        self.pending_qtokens.push(qt);
        Ok(())
    }

    /// ==================== HANDLE методы (обработка результатов) ====================

    pub fn handle_accept(&mut self, qr: &demi_qresult_t) -> Result<QDesc> {
        let new_qd: QDesc = unsafe { qr.qr_value.ares.qd.into() };
        self.connected_clients.insert(new_qd);
        Ok(new_qd)
    }

    pub fn handle_pop(&mut self, qr: &demi_qresult_t) -> Result<(QDesc, Vec<u8>)> {
        let qd: QDesc = qr.qr_qd.into();
        let sga: demi_sgarray_t = unsafe { qr.qr_value.sga };

        // Собираем данные из сегментов
        let mut data = Vec::new();
        for i in 0..sga.num_segments as usize {
            let seg = sga.segments[i];
            if !seg.data_buf_ptr.is_null() && seg.data_len_bytes > 0 {
                let slice =
                    unsafe { std::slice::from_raw_parts(seg.data_buf_ptr as *const u8, seg.data_len_bytes as usize) };
                data.extend_from_slice(slice);
            }
        }

        // Освобождаем SGA после чтения
        self.libos.sgafree(sga)?;

        Ok((qd, data))
    }

    pub fn handle_push(&mut self) -> Result<()> {
        // PUSH завершён — ничего не делаем, данные уже в сети
        Ok(())
    }

    fn handle_fail(&mut self, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let errno: i64 = qr.qr_ret;

        if is_closed(errno) {
            self.handle_close(qd)?;
        } else {
            log::warn!("Operation failed, ignoring (qd={:?}, errno={:?})", qd, errno);
        }
        Ok(())
    }

    fn handle_close(&mut self, qd: QDesc) -> Result<()> {
        if self.connected_clients.remove(&qd) {
            self.libos.close(qd)?;
        }
        Ok(())
    }

    /// ==================== Публичные методы ====================

    /// Асинхронный accept: возвращает (QDesc, SocketAddr) принятого клиента

    pub fn run(&mut self) -> Result<()> {
        // 1. Инициализируем прослушивание (один раз)
        log::info!("[SERVER] Starting event loop on qd={:?}", self.listening_sockqd);
        self.issue_accept()?;

        loop {
            // 2. Ждем событий. Таймаут можно уменьшить до 1-10мс для отзывчивости
            match self
                .libos
                .wait_any(&self.pending_qtokens, Some(Duration::from_millis(10)))
            {
                Ok((index, qr)) => {
                    let _qt = self.pending_qtokens.remove(index);
                    let opcode = &qr.qr_opcode;
                    let qd: QDesc = qr.qr_qd.into();

                    match opcode {
                        demi_opcode_t::DEMI_OPC_ACCEPT => {
                            let new_qd = self.handle_accept(&qr)?;
                            let remote_addr = self.extract_remote_addr(&qr)?;

                            log::info!("[ACCEPT] New client: addr={}, qd={:?}", remote_addr, new_qd);

                            // Сразу начинаем ждать данные от клиента
                            self.issue_pop(new_qd)?;
                            // И сразу готовы принять следующее соединение
                            self.issue_accept()?;
                        },

                        // demi_opcode_t::DEMI_OPC_POP => {
                        //     let (pop_qd, data) = self.handle_pop(&qr)?;
                        //     if data.is_empty() {
                        //         log::info!("[POP] Client {:?} closed connection (EOF)", pop_qd);
                        //         self.close_connection(pop_qd)?;
                        //     }
                        //     // 2. Проверка на символ переноса строки (Enter)
                        //     else if data == b"\n" || data == b"\r\n" {
                        //         log::info!(
                        //             "[POP] Client {:?} sent Empty Line, closing by logic",
                        //             pop_qd
                        //         );
                        //         self.close_connection(pop_qd)?;
                        //     } else {
                        //         log::info!("[POP] Received {} bytes from {:?}", data.len(), pop_qd);
                        //         // Обработка логики (например, Echo)
                        //         self.process_message(pop_qd, data)?;

                        //         // ВАЖНО: сразу переподписываемся на POP,
                        //         // чтобы не пропустить следующий пакет
                        //         if self.connected_clients.contains(&pop_qd) {
                        //             self.issue_pop(pop_qd)?;
                        //         }
                        //     }
                        // }
                        demi_opcode_t::DEMI_OPC_POP => {
                            let qd: QDesc = qr.qr_qd.into();
                            let mut sga: demi_sgarray_t = unsafe { qr.qr_value.sga };

                            // 1. Проверяем последний сегмент на EOF
                            let closing = if sga.num_segments > 0
                                && sga.segments[sga.num_segments as usize - 1].data_len_bytes == 0
                            {
                                log::info!("[POP] Client {:?} closed connection (EOF)", qd);
                                sga.num_segments -= 1; // убираем пустой сегмент
                                true
                            } else {
                                false
                            };

                            // 2. Если есть данные, пушим их
                            if sga.num_segments > 0 {
                                self.process_sga(qd, &sga)?; // заменяет issue_push / обработку
                            }

                            // 3. Освобождаем память sgarray
                            self.libos.sgafree(sga)?;

                            // 4. Если клиент закрыл соединение, закрываем
                            if closing {
                                self.close_connection(qd)?;
                            } else {
                                // иначе продолжаем читать данные
                                self.issue_pop(qd)?;
                            }
                        },
                        demi_opcode_t::DEMI_OPC_PUSH => {
                            log::debug!("[PUSH] Data sent to {:?}", qd);
                            // Здесь можно вызвать sgafree, если вы используете асинхронный push
                        },

                        demi_opcode_t::DEMI_OPC_FAILED => {
                            log::error!("[FAILED] Operation failed on qd={:?}, errno={}", qd, qr.qr_ret);
                            self.handle_fail(&qr)?;
                        },
                        _ => {},
                    }
                },
                Err(e) if e.errno == libc::ETIMEDOUT => {
                    // Вместо yield_now в высокопроизводительных стеках
                    // часто используют просто продолжение цикла
                    continue;
                },
                Err(e) => bail!("Fatal error in wait_any: {:?}", e),
            }
        }
    }

    /// Извлечение адреса клиента из результата accept
    fn extract_remote_addr(&self, qr: &demi_qresult_t) -> Result<SocketAddr> {
        use libc::{sockaddr, sockaddr_in};
        use std::net::{IpAddr, Ipv4Addr};

        let sockaddr_ptr = &unsafe { qr.qr_value.ares.addr } as *const sockaddr;
        let sockaddr_in_ptr = sockaddr_ptr as *const sockaddr_in;
        let sockaddr_in = unsafe { *sockaddr_in_ptr };

        let ip = u32::from_be(sockaddr_in.sin_addr.s_addr);
        let port = u16::from_be(sockaddr_in.sin_port);
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
    }

    fn process_sga(&mut self, qd: QDesc, sga: &demi_sgarray_t) -> Result<()> {
        // 1. Проходим по сегментам sga
        for i in 0..sga.num_segments as usize {
            let segment = &sga.segments[i];
            if segment.data_len_bytes == 0 {
                continue; // пустой сегмент — пропускаем
            }

            // Преобразуем сегмент в слайс
            let slice = unsafe {
                std::slice::from_raw_parts(segment.data_buf_ptr as *const u8, segment.data_len_bytes as usize)
            };

            // Для удобства превратим в строку (если это текст)
            let msg = String::from_utf8_lossy(slice);
            log::info!("[PROCESS] Data from {:?}: {:?}", qd, msg.trim());

            // --- Пример ECHO логики ---
            // Отправляем сегмент обратно клиенту
            self.send_async(qd, slice)?;
            log::debug!("[PROCESS] Echo response issued for qd={:?}, segment={}", qd, i);
        }

        Ok(())
    }

    /// Асинхронная отправка (неблокирующая, добавляет в pending)
    pub fn send_async(&mut self, qd: QDesc, data: &[u8]) -> Result<()> {
        if !self.connected_clients.contains(&qd) {
            bail!("QDesc {:?} is not a connected client", qd);
        }
        let sga = self.make_sgarray(data)?;
        self.issue_push(qd, &sga)?;
        Ok(())
    }

    /// Закрытие конкретного соединения
    pub fn close_connection(&mut self, qd: QDesc) -> Result<()> {
        self.handle_close(qd)
    }

    /// Геттеры
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn connected_count(&self) -> usize {
        self.connected_clients.len()
    }

    pub fn try_clear_token(&mut self, qt: QToken) -> bool {
        if let Some(pos) = self.pending_qtokens.iter().position(|&x| x == qt) {
            self.pending_qtokens.swap_remove(pos);
            return true;
        }
        false
    }
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        // Закрываем все клиентские соединения
        for qd in self.connected_clients.drain().collect::<Vec<_>>() {
            self.libos.close(qd).ok();
        }
        // Закрываем слушающий сокет
        self.libos.close(self.listening_sockqd).ok();
    }
}

/// Проверка кодов ошибок на "закрытие соединения"
fn is_closed(ret: i64) -> bool {
    match ret as i32 {
        libc::ECONNRESET | libc::ENOTCONN | libc::ECANCELED | libc::EBADF => true,
        _ => false,
    }
}
