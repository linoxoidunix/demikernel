// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::demikernel::config::Config;
use ::std::net::Ipv4Addr;

//======================================================================================================================
// Structures
//======================================================================================================================

#[derive(Clone, Debug)]
pub struct Ipv4Config {
    gateway_ipv4_addr: Ipv4Addr,
    local_netmask: Ipv4Addr,
}

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl Ipv4Config {
    pub fn new(config: &Config) -> Self {
        Self {
            // Если gateway_ipv4_addr() вернул None, ставим 0.0.0.0
            gateway_ipv4_addr: config.gateway_ipv4_addr().unwrap_or(Ipv4Addr::UNSPECIFIED),

            // Если маски нет, ставим "полную" маску (все биты 1),
            // что фактически заставит стек считать любой другой IP внешним.
            // Или поставь 255.255.255.0 как наиболее вероятный дефолт.
            local_netmask: config.local_netmask().unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
        }
    }

    // Вспомогательный метод, чтобы проверять, настроен ли шлюз вообще
    pub fn is_gateway_setup(&self) -> bool {
        !self.gateway_ipv4_addr.is_unspecified()
    }

    pub fn gateway_ipv4_addr(&self) -> Ipv4Addr {
        self.gateway_ipv4_addr
    }

    pub fn local_netmask(&self) -> Ipv4Addr {
        self.local_netmask
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Default for Ipv4Config {
    fn default() -> Self {
        Self {
            // Значения по умолчанию для типичных домашних сетей,
            // хотя в идеале пользователь должен их переопределить.
            gateway_ipv4_addr: Ipv4Addr::UNSPECIFIED,
            local_netmask: Ipv4Addr::new(255, 255, 255, 0),
        }
    }
}
