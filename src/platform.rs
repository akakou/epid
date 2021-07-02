use super::core::{GPK, ISK};

pub struct Platform {
    pub gpk: GPK,
}

impl Platform {
    pub fn new(gpk: GPK) -> Self {
        Self {gpk}
    }
}
