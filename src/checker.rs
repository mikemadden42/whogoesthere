use crate::finding::Finding;

pub trait Checker {
    fn name(&self) -> &'static str;
    fn run(&self) -> Vec<Finding>;
}
