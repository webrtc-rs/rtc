/// NoOp is an Interceptor that does not modify any packets. It can be embedded in other interceptors, so it's
/// possible to implement only a subset of the methods.
struct NoOp;

impl Interceptor for NoOp {
    fn chain(self: Box<Self>, _next: Box<dyn Interceptor>) -> Box<dyn Interceptor> {
        self
    }

    fn next(&mut self) -> Option<&mut Box<dyn Interceptor>> {
        None
    }
}
