/// FIR: asks a sender for a full intra frame, used when a receiver joins or resyncs.
pub mod full_intra_request;
/// PLI: tells a sender the receiver lost picture and needs a keyframe.
pub mod picture_loss_indication;
/// REMB: the receiver's estimate of the bitrate the path can carry.
pub mod receiver_estimated_maximum_bitrate;
/// SLI: reports individual lost slices, for finer-grained repair than PLI.
pub mod slice_loss_indication;
