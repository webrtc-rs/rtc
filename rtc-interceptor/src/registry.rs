/// InterceptorBuilder provides an interface for constructing interceptors
pub trait InterceptorBuilder {
    fn build(&self, id: &str) -> Box<dyn Interceptor>;
}

/// Registry is a collector for interceptors.
#[derive(Default)]
pub struct Registry {
    builders: Vec<Box<dyn InterceptorBuilder + Send + Sync>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// add_front a new InterceptorBuilder to the front of interceptors in the registry.
    pub fn add_front(&mut self, builder: Box<dyn InterceptorBuilder + Send + Sync>) {
        self.builders.insert(0, builder);
    }

    /// add_back a new InterceptorBuilder to the back of interceptors in the registry.
    pub fn add_back(&mut self, builder: Box<dyn InterceptorBuilder + Send + Sync>) {
        self.builders.push(builder);
    }

    /// build a single Interceptor from an InterceptorRegistry
    pub fn build(&self, id: &str) -> Box<dyn Interceptor> {
        let mut next = Box::new(NoOp) as Box<dyn Interceptor>;
        for interceptor in self.builders.iter().rev().map(|b| b.build(id)) {
            next = interceptor.chain(next);
        }
        next
    }
}
