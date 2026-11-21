//! BRK2 binary envelope and TLV codec for Rakshas broker interoperability.
//! Frames use a 4-byte big-endian body length, a fixed 32-byte header, and TLV fields.
//! The length excludes the four-byte prefix. No unsafe code or external dependencies.

use std::{collections::HashMap, fmt};

pub const MAGIC: &[u8; 4] = b"BRK2";
pub const HEADER_LEN: usize = 32;
pub const TLV_HEADER_LEN: usize = 8;
pub const DEFAULT_MAX_FRAME: usize = 1_048_576;
pub const DEFAULT_MAX_PAYLOAD: usize = 524_288;
pub const MAX_FIELDS: usize = 4096;

pub const MSG_HELLO: u16 = 1;
pub const MSG_HELLO_ACK: u16 = 2;
pub const MSG_REQUEST: u16 = 3;
pub const MSG_RESPONSE: u16 = 4;
pub const MSG_ERROR: u16 = 5;
pub const MSG_CANCEL: u16 = 6;
pub const MSG_CANCEL_ACK: u16 = 7;
pub const MSG_PING: u16 = 8;
pub const MSG_PONG: u16 = 9;
pub const MSG_GOAWAY: u16 = 10;
pub const MSG_WINDOW_UPDATE: u16 = 11;

pub const SCHEMA_BROKER_REQUEST: u32 = 1;
pub const SCHEMA_BROKER_RESPONSE: u32 = 2;
pub const FLAG_RESPONSE: u16 = 1;
pub const FLAG_ERROR: u16 = 2;
pub const FLAG_END_STREAM: u16 = 4;
pub const FLAG_COMPRESSED: u16 = 8;
pub const FLAG_AUTHENTICATED: u16 = 16;
pub const FLAG_IDEMPOTENT: u16 = 32;
pub const FLAG_CANCELLATION: u16 = 64;
pub const FLAG_MORE_FRAGMENTS: u16 = 128;
pub const KNOWN_FLAGS: u16 = 0x00ff;
pub const FIELD_CRITICAL: u8 = 1;
pub const FIELD_REPEATED: u8 = 2;
const KNOWN_FIELD_FLAGS: u8 = FIELD_CRITICAL | FIELD_REPEATED;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType { U8=1, U16=2, U32=3, U64=4, I64=5, F32=6, F64=7, Utf8=8, Bytes=9, Bool=10, Nested=11, Uuid=12 }
impl TryFrom<u8> for WireType {
    type Error = Error;
    fn try_from(v:u8)->Result<Self,Error>{ Ok(match v {1=>Self::U8,2=>Self::U16,3=>Self::U32,4=>Self::U64,5=>Self::I64,6=>Self::F32,7=>Self::F64,8=>Self::Utf8,9=>Self::Bytes,10=>Self::Bool,11=>Self::Nested,12=>Self::Uuid,_=>return Err(Error::UnknownWireType(v))}) }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str), BadMagic, UnsupportedMajor(u8), InvalidHeaderLength(u16),
    ReservedNonZero, FrameTooLarge(usize), PayloadTooLarge(usize), LengthMismatch,
    UnknownWireType(u8), InvalidFieldFlags(u8), InvalidMessageFlags(u16),
    InvalidFieldLength{field_id:u16,expected:usize,actual:usize}, InvalidUtf8(u16),
    InvalidBoolean(u16), UnknownCriticalField(u16), DuplicateSingularField(u16),
    TooManyFields, MissingField(u16), WrongWireType{field_id:u16,expected:WireType,actual:WireType},
    InvalidValue(&'static str), TrailingBytes,
}
impl fmt::Display for Error { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"BRK2 codec error: {self:?}") } }
impl std::error::Error for Error {}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Limits { pub max_frame_bytes:usize, pub max_payload_bytes:usize, pub max_fields:usize }
impl Default for Limits { fn default()->Self { Self{max_frame_bytes:DEFAULT_MAX_FRAME,max_payload_bytes:DEFAULT_MAX_PAYLOAD,max_fields:MAX_FIELDS} } }

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Header { pub major:u8,pub minor:u8,pub message_type:u16,pub flags:u16,pub request_id:u64,pub schema_id:u32,pub schema_version:u16 }
impl Header { pub fn new(message_type:u16,request_id:u64,schema_id:u32,schema_version:u16)->Self { Self{major:2,minor:0,message_type,flags:0,request_id,schema_id,schema_version} } }

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Field { pub id:u16,pub wire_type:WireType,pub flags:u8,pub value:Vec<u8> }
impl Field {
    pub fn new(id:u16,wire_type:WireType,value:Vec<u8>)->Self { Self{id,wire_type,flags:0,value} }
    pub fn critical(mut self)->Self { self.flags|=FIELD_CRITICAL; self }
    pub fn repeated(mut self)->Self { self.flags|=FIELD_REPEATED; self }
    pub fn utf8(id:u16,s:&str)->Self { Self::new(id,WireType::Utf8,s.as_bytes().to_vec()) }
    pub fn bytes(id:u16,b:&[u8])->Self { Self::new(id,WireType::Bytes,b.to_vec()) }
    pub fn u8(id:u16,v:u8)->Self { Self::new(id,WireType::U8,vec![v]) }
    pub fn u16(id:u16,v:u16)->Self { Self::new(id,WireType::U16,v.to_be_bytes().to_vec()) }
    pub fn u32(id:u16,v:u32)->Self { Self::new(id,WireType::U32,v.to_be_bytes().to_vec()) }
    pub fn u64(id:u16,v:u64)->Self { Self::new(id,WireType::U64,v.to_be_bytes().to_vec()) }
    pub fn uuid(id:u16,v:[u8;16])->Self { Self::new(id,WireType::Uuid,v.to_vec()) }
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Message { pub header:Header,pub fields:Vec<Field> }
impl Message { pub fn new(header:Header)->Self { Self{header,fields:Vec::new()} } pub fn push(&mut self,f:Field){self.fields.push(f)} pub fn field(&self,id:u16)->Option<&Field>{self.fields.iter().find(|f|f.id==id)} }

fn validate_value(f:&Field)->Result<(),Error>{
    let expected=match f.wire_type { WireType::U8|WireType::Bool=>Some(1),WireType::U16=>Some(2),WireType::U32|WireType::F32=>Some(4),WireType::U64|WireType::I64|WireType::F64=>Some(8),WireType::Utf8|WireType::Bytes|WireType::Uuid|WireType::Nested=>None };
    if let Some(n)=expected { if f.value.len()!=n { return Err(Error::InvalidFieldLength{field_id:f.id,expected:n,actual:f.value.len()}); } }
    match f.wire_type {
        WireType::Utf8=>{std::str::from_utf8(&f.value).map_err(|_|Error::InvalidUtf8(f.id))?;}
        WireType::Bool if f.value[0]>1=>return Err(Error::InvalidBoolean(f.id)),
        WireType::F32 if !f32::from_bits(u32::from_be_bytes(f.value[..4].try_into().unwrap())).is_finite()=>return Err(Error::InvalidValue("non-finite f32")),
        WireType::F64 if !f64::from_bits(u64::from_be_bytes(f.value[..8].try_into().unwrap())).is_finite()=>return Err(Error::InvalidValue("non-finite f64")),
        _=>{}
    } Ok(())
}
fn validate_duplicates(fields:&[Field])->Result<(),Error>{
    let mut seen=HashMap::<u16,bool>::new();
    for f in fields { if f.flags & !KNOWN_FIELD_FLAGS!=0{return Err(Error::InvalidFieldFlags(f.flags))}
        let repeated=f.flags&FIELD_REPEATED!=0;
        if let Some(prev)=seen.get(&f.id) {if !repeated||!*prev{return Err(Error::DuplicateSingularField(f.id))}} else {seen.insert(f.id,repeated);}
    }
    Ok(())
}
pub fn encode(m:&Message,limits:Limits)->Result<Vec<u8>,Error>{
    if m.header.major!=2{return Err(Error::UnsupportedMajor(m.header.major))}
    if m.header.flags & !KNOWN_FLAGS!=0{return Err(Error::InvalidMessageFlags(m.header.flags))}
    if m.fields.len()>limits.max_fields{return Err(Error::TooManyFields)}
    validate_duplicates(&m.fields)?;
    let mut payload=Vec::new();
    for f in &m.fields {validate_value(f)?;let n=u32::try_from(f.value.len()).map_err(|_|Error::PayloadTooLarge(f.value.len()))?;
        payload.extend_from_slice(&f.id.to_be_bytes());payload.push(f.wire_type as u8);payload.push(f.flags);payload.extend_from_slice(&n.to_be_bytes());payload.extend_from_slice(&f.value);}
    if payload.len()>limits.max_payload_bytes{return Err(Error::PayloadTooLarge(payload.len()))}
    let body_len=HEADER_LEN.checked_add(payload.len()).ok_or(Error::FrameTooLarge(usize::MAX))?;
    if body_len>limits.max_frame_bytes{return Err(Error::FrameTooLarge(body_len))}
    let mut out=Vec::with_capacity(4+body_len);out.extend_from_slice(&(u32::try_from(body_len).map_err(|_|Error::FrameTooLarge(body_len))?).to_be_bytes());
    out.extend_from_slice(MAGIC);out.push(m.header.major);out.push(m.header.minor);out.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    out.extend_from_slice(&m.header.message_type.to_be_bytes());out.extend_from_slice(&m.header.flags.to_be_bytes());out.extend_from_slice(&m.header.request_id.to_be_bytes());
    out.extend_from_slice(&m.header.schema_id.to_be_bytes());out.extend_from_slice(&m.header.schema_version.to_be_bytes());out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());out.extend_from_slice(&payload);Ok(out)
}
pub fn decode(input:&[u8],limits:Limits)->Result<Message,Error>{
    if input.len()<4{return Err(Error::Truncated("frame prefix"))}
    let len=u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    if len>limits.max_frame_bytes{return Err(Error::FrameTooLarge(len))}
    if len<HEADER_LEN{return Err(Error::Truncated("fixed header"))}
    if input.len()<4+len{return Err(Error::Truncated("frame body"))}
    if input.len()!=4+len{return Err(Error::TrailingBytes)}
    let b=&input[4..];if &b[..4]!=MAGIC{return Err(Error::BadMagic)}
    let major=b[4];if major!=2{return Err(Error::UnsupportedMajor(major))}
    let minor=b[5];let hlen=u16::from_be_bytes(b[6..8].try_into().unwrap());if hlen!=HEADER_LEN as u16{return Err(Error::InvalidHeaderLength(hlen))}
    let message_type=u16::from_be_bytes(b[8..10].try_into().unwrap());let flags=u16::from_be_bytes(b[10..12].try_into().unwrap());
    if flags & !KNOWN_FLAGS!=0{return Err(Error::InvalidMessageFlags(flags))}
    let request_id=u64::from_be_bytes(b[12..20].try_into().unwrap());let schema_id=u32::from_be_bytes(b[20..24].try_into().unwrap());
    let schema_version=u16::from_be_bytes(b[24..26].try_into().unwrap());if u16::from_be_bytes(b[26..28].try_into().unwrap())!=0{return Err(Error::ReservedNonZero)}
    let plen=u32::from_be_bytes(b[28..32].try_into().unwrap()) as usize;if plen>limits.max_payload_bytes{return Err(Error::PayloadTooLarge(plen))}
    if HEADER_LEN.checked_add(plen)!=Some(len){return Err(Error::LengthMismatch)}
    let mut fields=Vec::new();let mut p=HEADER_LEN;let mut seen=HashMap::<u16,bool>::new();
    while p<b.len(){
        if fields.len()>=limits.max_fields{return Err(Error::TooManyFields)}
        if b.len()-p<TLV_HEADER_LEN{return Err(Error::Truncated("TLV header"))}
        let id=u16::from_be_bytes(b[p..p+2].try_into().unwrap());let wt=WireType::try_from(b[p+2])?;let ff=b[p+3];
        if ff & !KNOWN_FIELD_FLAGS!=0{return Err(Error::InvalidFieldFlags(ff))}
        let repeated=ff&FIELD_REPEATED!=0;
        if let Some(prev)=seen.get(&id){
            if !repeated||!*prev{return Err(Error::DuplicateSingularField(id));}
        } else {
            seen.insert(id,repeated);
        }
        let n=u32::from_be_bytes(b[p+4..p+8].try_into().unwrap()) as usize;p+=TLV_HEADER_LEN;
        let end=p.checked_add(n).ok_or(Error::LengthMismatch)?;if end>b.len(){return Err(Error::Truncated("TLV value"))}
        let field=Field{id,wire_type:wt,flags:ff,value:b[p..end].to_vec()};
        validate_value(&field)?;
        fields.push(field);p=end;
    }
    Ok(Message{header:Header{major,minor,message_type,flags,request_id,schema_id,schema_version},fields})
}
pub fn validate_known_fields(m:&Message,known:&[(u16,WireType,bool)])->Result<(),Error>{
    for f in &m.fields {if let Some((_,expected,_))=known.iter().find(|(id,_,_)|*id==f.id){if f.wire_type!=*expected{return Err(Error::WrongWireType{field_id:f.id,expected:*expected,actual:f.wire_type})}}else if f.flags&FIELD_CRITICAL!=0{return Err(Error::UnknownCriticalField(f.id))}}
    for (id,_,required) in known{if *required&&m.field(*id).is_none(){return Err(Error::MissingField(*id))}}Ok(())
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlacementMode { Prefer=1, Bind=2, Interleave=3 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlacementOutcome { Honored=1, Rejected=2, Fallback=3 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PlacementReason {
    UnsupportedScope=1, UnsupportedMode=2, LocalityDomainMismatch=3, NodeUnavailable=4,
    ProcessPolicyDenied=5, MemoryQuota=6, AllocatorUnavailable=7, SizeLimit=8, PlacementFailed=9,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementIntent { pub mode:PlacementMode, pub numa_node:Option<u32>, pub max_bytes:u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementResult { pub outcome:PlacementOutcome, pub applied_numa_node:Option<u32>, pub reason:Option<PlacementReason> }

fn nested_fields(bytes:&[u8], max_fields:usize)->Result<Vec<Field>,Error>{
    let mut out=Vec::new(); let mut seen=HashMap::<u16,bool>::new(); let mut p=0usize;
    while p<bytes.len(){
        if out.len()>=max_fields{return Err(Error::TooManyFields)}
        if bytes.len()-p<TLV_HEADER_LEN{return Err(Error::Truncated("nested TLV header"))}
        let id=u16::from_be_bytes(bytes[p..p+2].try_into().unwrap());
        let wire_type=WireType::try_from(bytes[p+2])?; let flags=bytes[p+3];
        if flags & !KNOWN_FIELD_FLAGS!=0{return Err(Error::InvalidFieldFlags(flags))}
        let repeated=flags&FIELD_REPEATED!=0;
        if let Some(prev)=seen.get(&id){if !repeated||!*prev{return Err(Error::DuplicateSingularField(id))}}
        else{seen.insert(id,repeated);}
        let n=u32::from_be_bytes(bytes[p+4..p+8].try_into().unwrap()) as usize;p+=8;
        let end=p.checked_add(n).ok_or(Error::LengthMismatch)?;
        if end>bytes.len(){return Err(Error::Truncated("nested TLV value"))}
        let f=Field{id,wire_type,flags,value:bytes[p..end].to_vec()};validate_value(&f)?;
        out.push(f);p=end;
    } Ok(out)
}
fn nested_get<'a>(fields:&'a [Field],id:u16,wt:WireType)->Result<&'a Field,Error>{
    let f=fields.iter().find(|f|f.id==id).ok_or(Error::MissingField(id))?;
    if f.wire_type!=wt{return Err(Error::WrongWireType{field_id:id,expected:wt,actual:f.wire_type})} Ok(f)
}
fn nested_encode(fields:&[Field])->Result<Vec<u8>,Error>{
    validate_duplicates(fields)?;let mut out=Vec::new();
    for f in fields{validate_value(f)?;let n=u32::try_from(f.value.len()).map_err(|_|Error::PayloadTooLarge(f.value.len()))?;
        out.extend_from_slice(&f.id.to_be_bytes());out.push(f.wire_type as u8);out.push(f.flags);
        out.extend_from_slice(&n.to_be_bytes());out.extend_from_slice(&f.value);}
    Ok(out)
}
/// Attach field 14. Older peers may ignore non-critical prefer; mandatory modes fail closed.
pub fn set_placement_intent(m:&mut Message,v:PlacementIntent)->Result<(),Error>{
    if m.header.message_type!=MSG_REQUEST||m.header.schema_id!=SCHEMA_BROKER_REQUEST{return Err(Error::InvalidValue("placement intent requires broker request"))}
    if m.field(14).is_some(){return Err(Error::DuplicateSingularField(14))}
    if v.max_bytes==0{return Err(Error::InvalidValue("placement max_bytes must be nonzero"))}
    let payload_len=m.field(7).ok_or(Error::MissingField(7))?.value.len();
    if v.max_bytes>payload_len as u64{return Err(Error::InvalidValue("placement max_bytes exceeds request payload"))}
    match v.mode{PlacementMode::Prefer|PlacementMode::Bind if v.numa_node.is_none()=>return Err(Error::InvalidValue("prefer/bind requires NUMA node")),
        PlacementMode::Interleave if v.numa_node.is_some()=>return Err(Error::InvalidValue("interleave must not name one NUMA node")),_=>{}}
    let mut fs=vec![Field::u16(1,1),Field::u8(2,1),Field::u8(3,v.mode as u8)];
    if let Some(n)=v.numa_node{fs.push(Field::u32(4,n));} fs.push(Field::u64(5,v.max_bytes));
    let mut outer=Field::new(14,WireType::Nested,nested_encode(&fs)?);
    if v.mode!=PlacementMode::Prefer{outer=outer.critical();} m.push(outer);Ok(())
}
/// Decode field 14. payload_bytes is the already-bounded decoded request payload size.
pub fn placement_intent(m:&Message,payload_bytes:usize)->Result<Option<PlacementIntent>,Error>{
    let Some(outer)=m.field(14) else{return Ok(None)};
    if outer.flags&FIELD_REPEATED!=0{return Err(Error::InvalidValue("placement request field must be singular"))}
    if outer.wire_type!=WireType::Nested{return Err(Error::WrongWireType{field_id:14,expected:WireType::Nested,actual:outer.wire_type})}
    let fs=nested_fields(&outer.value,16)?;
    for f in &fs{if (1..=5).contains(&f.id)&&f.flags&FIELD_REPEATED!=0{return Err(Error::InvalidValue("known placement fields are singular"))} if !(1..=5).contains(&f.id)&&f.flags&FIELD_CRITICAL!=0{return Err(Error::UnknownCriticalField(f.id))}}
    if u16::from_be_bytes(nested_get(&fs,1,WireType::U16)?.value[..2].try_into().unwrap())!=1{return Err(Error::InvalidValue("unsupported placement version"))}
    if nested_get(&fs,2,WireType::U8)?.value[0]!=1{return Err(Error::InvalidValue("unsupported placement scope"))}
    let mode=match nested_get(&fs,3,WireType::U8)?.value[0]{1=>PlacementMode::Prefer,2=>PlacementMode::Bind,3=>PlacementMode::Interleave,_=>return Err(Error::InvalidValue("unsupported placement mode"))};
    let node=fs.iter().find(|f|f.id==4).map(|f|{if f.wire_type!=WireType::U32{return Err(Error::WrongWireType{field_id:4,expected:WireType::U32,actual:f.wire_type})}Ok(u32::from_be_bytes(f.value[..4].try_into().unwrap()))}).transpose()?;
    let max_bytes=u64::from_be_bytes(nested_get(&fs,5,WireType::U64)?.value[..8].try_into().unwrap());
    if max_bytes==0||max_bytes>payload_bytes as u64{return Err(Error::InvalidValue("placement max_bytes exceeds payload"))}
    match mode{PlacementMode::Prefer|PlacementMode::Bind if node.is_none()=>return Err(Error::InvalidValue("prefer/bind requires NUMA node")),
        PlacementMode::Interleave if node.is_some()=>return Err(Error::InvalidValue("interleave must not name one NUMA node")),_=>{}}
    if (outer.flags&FIELD_CRITICAL!=0)!=(mode!=PlacementMode::Prefer){return Err(Error::InvalidValue("placement critical flag/mode mismatch"))}
    Ok(Some(PlacementIntent{mode,numa_node:node,max_bytes}))
}
/// Attach response field 13 with allocator-verified outcome. No outcome means unknown.
pub fn set_placement_result(m:&mut Message,v:PlacementResult)->Result<(),Error>{
    if m.header.message_type!=MSG_RESPONSE||m.header.schema_id!=SCHEMA_BROKER_RESPONSE{return Err(Error::InvalidValue("placement result requires broker response"))}
    if m.field(13).is_some(){return Err(Error::DuplicateSingularField(13))}
    if (v.outcome==PlacementOutcome::Honored&&v.reason.is_some())||(v.outcome!=PlacementOutcome::Honored&&v.reason.is_none()){return Err(Error::InvalidValue("placement outcome/reason mismatch"))}
    if v.outcome==PlacementOutcome::Rejected && v.applied_numa_node.is_some(){return Err(Error::InvalidValue("rejected placement cannot report an applied NUMA node"))}
    let mut fs=vec![Field::u16(1,1),Field::u8(2,1),Field::u8(3,v.outcome as u8)];
    if let Some(n)=v.applied_numa_node{fs.push(Field::u32(4,n))}
    if let Some(r)=v.reason{fs.push(Field::u16(5,r as u16))}
    m.push(Field::new(13,WireType::Nested,nested_encode(&fs)?));Ok(())
}
/// Decode response field 13. Absence is unknown/not applied, never success.
pub fn placement_result(m:&Message)->Result<Option<PlacementResult>,Error>{
    let Some(outer)=m.field(13) else{return Ok(None)};
    if outer.flags&FIELD_REPEATED!=0{return Err(Error::InvalidValue("placement result field must be singular"))}
    if outer.wire_type!=WireType::Nested{return Err(Error::WrongWireType{field_id:13,expected:WireType::Nested,actual:outer.wire_type})}
    let fs=nested_fields(&outer.value,16)?;
    for f in &fs{if !(1..=5).contains(&f.id)&&f.flags&FIELD_CRITICAL!=0{return Err(Error::UnknownCriticalField(f.id))}}
    if u16::from_be_bytes(nested_get(&fs,1,WireType::U16)?.value[..2].try_into().unwrap())!=1||nested_get(&fs,2,WireType::U8)?.value[0]!=1{return Err(Error::InvalidValue("unsupported placement result version/scope"))}
    let outcome=match nested_get(&fs,3,WireType::U8)?.value[0]{1=>PlacementOutcome::Honored,2=>PlacementOutcome::Rejected,3=>PlacementOutcome::Fallback,_=>return Err(Error::InvalidValue("unknown placement outcome"))};
    let node=fs.iter().find(|f|f.id==4).map(|f|{if f.wire_type!=WireType::U32{return Err(Error::WrongWireType{field_id:4,expected:WireType::U32,actual:f.wire_type})}Ok(u32::from_be_bytes(f.value[..4].try_into().unwrap()))}).transpose()?;
    let reason=fs.iter().find(|f|f.id==5).map(|f|{if f.wire_type!=WireType::U16{return Err(Error::WrongWireType{field_id:5,expected:WireType::U16,actual:f.wire_type})}
        Ok(match u16::from_be_bytes(f.value[..2].try_into().unwrap()){1=>PlacementReason::UnsupportedScope,2=>PlacementReason::UnsupportedMode,3=>PlacementReason::LocalityDomainMismatch,4=>PlacementReason::NodeUnavailable,5=>PlacementReason::ProcessPolicyDenied,6=>PlacementReason::MemoryQuota,7=>PlacementReason::AllocatorUnavailable,8=>PlacementReason::SizeLimit,9=>PlacementReason::PlacementFailed,_=>return Err(Error::InvalidValue("unknown placement reason"))})}).transpose()?;
    if (outcome==PlacementOutcome::Honored&&reason.is_some())||(outcome!=PlacementOutcome::Honored&&reason.is_none()){return Err(Error::InvalidValue("placement outcome/reason mismatch"))}
    Ok(Some(PlacementResult{outcome,applied_numa_node:node,reason}))
}

pub mod request_field {
    pub const TASK_ID:u16=1; pub const SOURCE:u16=2; pub const DESTINATION:u16=3;
    pub const KIND:u16=4; pub const PRIORITY:u16=5; pub const TIMEOUT_MS:u16=6;
    pub const PAYLOAD:u16=7; pub const IDEMPOTENCY_KEY:u16=8; pub const DEADLINE_UNIX_NS:u16=9;
    pub const DEVICE_PREFERENCE:u16=10; pub const WORKER_CLASS:u16=11;
    pub const SPATIAL_AFFINITY_KEY:u16=12; pub const PREFERRED_NUMA_NODE:u16=13;
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct BrokerRequest {
    pub task_id:String, pub source:String, pub destination:String, pub kind:String,
    pub priority:u8, pub timeout_ms:u32, pub payload:Vec<u8>,
    pub idempotency_key:Option<[u8;16]>, pub deadline_unix_ns:Option<u64>,
    pub device_preference:Option<String>, pub worker_class:Option<String>,
    pub spatial_affinity_key:Option<u64>, pub preferred_numa_node:Option<u32>,
}
impl BrokerRequest {
    pub fn to_message(&self,request_id:u64)->Message{let mut m=Message::new(Header::new(MSG_REQUEST,request_id,SCHEMA_BROKER_REQUEST,1));
        m.push(Field::utf8(1,&self.task_id).critical());m.push(Field::utf8(2,&self.source).critical());m.push(Field::utf8(3,&self.destination).critical());m.push(Field::utf8(4,&self.kind).critical());
        m.push(Field::u8(5,self.priority).critical());m.push(Field::u32(6,self.timeout_ms).critical());m.push(Field::bytes(7,&self.payload).critical());
        if let Some(v)=self.idempotency_key{m.push(Field::uuid(8,v));}
        if let Some(v)=self.deadline_unix_ns{m.push(Field::u64(9,v));}
        if let Some(v)=&self.device_preference{m.push(Field::utf8(10,v));}
        if let Some(v)=&self.worker_class{m.push(Field::utf8(11,v));}
        if let Some(v)=self.spatial_affinity_key{m.push(Field::u64(12,v));}
        if let Some(v)=self.preferred_numa_node{m.push(Field::u32(13,v));}
        m
    }
    pub fn from_message(m:&Message)->Result<Self,Error>{
        if m.header.message_type!=MSG_REQUEST||m.header.schema_id!=SCHEMA_BROKER_REQUEST{return Err(Error::InvalidValue("not a BrokerRequest"))}
        let schema=[
            (1,WireType::Utf8,true),(2,WireType::Utf8,true),(3,WireType::Utf8,true),
            (4,WireType::Utf8,true),(5,WireType::U8,true),(6,WireType::U32,true),
            (7,WireType::Bytes,true),(8,WireType::Uuid,false),(9,WireType::U64,false),
            (10,WireType::Utf8,false),(11,WireType::Utf8,false),(12,WireType::U64,false),
            (13,WireType::U32,false),(14,WireType::Nested,false)
        ];
        validate_known_fields(m,&schema)?;
        let _ = placement_intent(m, m.field(7).map_or(0, |f| f.value.len()))?;
        let s=|id:u16|->Result<String,Error>{Ok(std::str::from_utf8(&m.field(id).unwrap().value).map_err(|_|Error::InvalidUtf8(id))?.to_owned())};
        let task_id=s(1)?;let source=s(2)?;let destination=s(3)?;let kind=s(4)?;
        for (name,v) in [("task_id",&task_id),("source",&source),("destination",&destination),("kind",&kind)]{if v.trim().is_empty(){return Err(Error::InvalidValue(name))}}
        let timeout_ms=u32::from_be_bytes(m.field(6).unwrap().value[..4].try_into().unwrap());if timeout_ms==0{return Err(Error::InvalidValue("timeout_ms must be nonzero"))}
        let device_preference = m.field(10).map(|f| {std::str::from_utf8(&f.value).map(|value| value.to_owned()).map_err(|_| Error::InvalidUtf8(10))}).transpose()?;
        let worker_class = m.field(11).map(|f| {
            std::str::from_utf8(&f.value).map(|value| value.to_owned()).map_err(|_| Error::InvalidUtf8(11))
        }).transpose()?;
        if let Some(value) = &worker_class {
            if !matches!(value.as_str(), "control"|"realtime-spatial"|"throughput"|"exact-cpu"|"inference") {
                return Err(Error::InvalidValue("unknown worker_class"));
            }
        }
        let spatial_affinity_key = m.field(12).map(|f|u64::from_be_bytes(f.value[..8].try_into().unwrap()));
        let preferred_numa_node = m.field(13).map(|f|u32::from_be_bytes(f.value[..4].try_into().unwrap()));
        let deadline_unix_ns = m.field(9).map(|f|u64::from_be_bytes(f.value[..8].try_into().unwrap()));
        if deadline_unix_ns == Some(0) || deadline_unix_ns.is_some_and(|v| v > i64::MAX as u64) {
            return Err(Error::InvalidValue("deadline_unix_ns is outside the supported range"));
        }
        if worker_class.as_deref() == Some("realtime-spatial") && spatial_affinity_key.is_none() {
            return Err(Error::InvalidValue("realtime-spatial requires spatial_affinity_key"));
        }
        Ok(Self{
            task_id,source,destination,kind,priority:m.field(5).unwrap().value[0],
            timeout_ms,payload:m.field(7).unwrap().value.clone(),
            idempotency_key:m.field(8).map(|f|f.value.as_slice().try_into().unwrap()),
            deadline_unix_ns,device_preference,worker_class,spatial_affinity_key,preferred_numa_node
        })
    }
}

#[cfg(test)]
mod tests {
  use super::*;
  fn sample()->Message{BrokerRequest{task_id:"t-1".into(),source:"yukki".into(),destination:"broker".into(),kind:"inference".into(),priority:4,timeout_ms:5000,payload:vec![0,1,255],idempotency_key:None,deadline_unix_ns:None,device_preference:None,worker_class:None,spatial_affinity_key:None,preferred_numa_node:None}.to_message(0x0102030405060708)}
  #[test]fn round_trip_and_endian(){let m=sample();let b=encode(&m,Limits::default()).unwrap();assert_eq!(&b[4..8],b"BRK2");assert_eq!(&b[16..24],&0x0102030405060708u64.to_be_bytes());let decoded=decode(&b,Limits::default()).unwrap();assert_eq!(decoded.header.request_id,0x0102030405060708);assert_eq!(decoded.header.message_type,MSG_REQUEST);}
  #[test]fn request_schema_round_trip(){let m=sample();let r=BrokerRequest::from_message(&m).unwrap();assert_eq!(r.task_id,"t-1");assert_eq!(r.payload,vec![0,1,255]);}
  #[test]fn rejects_invalid_device_preference_utf8(){let mut m=sample();m.push(Field::new(10,WireType::Utf8,vec![0xff]));assert_eq!(BrokerRequest::from_message(&m), Err(Error::InvalidUtf8(10)));}
  #[test]fn rejects_truncation_and_trailing_bytes(){let mut b=encode(&sample(),Limits::default()).unwrap();b.pop();assert!(matches!(decode(&b,Limits::default()),Err(Error::Truncated(_))));b=encode(&sample(),Limits::default()).unwrap();b.push(0);assert!(matches!(decode(&b,Limits::default()),Err(Error::TrailingBytes)));}
  #[test]fn rejects_bad_magic_reserved_and_flags(){let mut b=encode(&sample(),Limits::default()).unwrap();b[4]=b'X';assert_eq!(decode(&b,Limits::default()),Err(Error::BadMagic));b=encode(&sample(),Limits::default()).unwrap();b[30]=1;assert_eq!(decode(&b,Limits::default()),Err(Error::ReservedNonZero));}
  #[test]fn rejects_duplicate_and_invalid_utf8(){let mut m=sample();m.push(Field::utf8(1,"dup"));assert_eq!(encode(&m,Limits::default()),Err(Error::DuplicateSingularField(1)));m=sample();m.fields.iter_mut().find(|f|f.id==1).unwrap().value = vec![0xff];assert_eq!(BrokerRequest::from_message(&m), Err(Error::InvalidUtf8(1)));}
  #[test]fn rejects_unknown_critical_but_preserves_optional(){let mut m=Message::new(Header::new(MSG_REQUEST,1,SCHEMA_BROKER_REQUEST,1));m.push(Field::utf8(1,"known").critical());m.push(Field::u8(99,1));assert!(validate_known_fields(&m,&[(1,WireType::Utf8,true)]).is_ok());m.fields.last_mut().unwrap().flags |= FIELD_CRITICAL;assert_eq!(validate_known_fields(&m,&[(1,WireType::Utf8,true)]),Err(Error::UnknownCriticalField(99)));}
  #[test]fn rejects_limits_and_zero_timeout(){let b=encode(&sample(),Limits::default()).unwrap();let l=Limits{max_frame_bytes:32,..Limits::default()};assert!(matches!(decode(&b,l),Err(Error::FrameTooLarge(_))));let mut bad=sample();bad.fields.iter_mut().find(|f|f.id==6).unwrap().value=0u32.to_be_bytes().to_vec();assert_eq!(BrokerRequest::from_message(&bad),Err(Error::InvalidValue("timeout_ms must be nonzero")));}
  #[test]fn locality_placement_intent_round_trip_and_legacy_flags(){
      let mut m=sample();let v=PlacementIntent{mode:PlacementMode::Prefer,numa_node:Some(2),max_bytes:3};
      set_placement_intent(&mut m,v).unwrap();assert_eq!(placement_intent(&m,3).unwrap(),Some(v));
      assert_eq!(m.field(14).unwrap().flags&FIELD_CRITICAL,0);
      let mut mandatory=sample();let b=PlacementIntent{mode:PlacementMode::Bind,numa_node:Some(1),max_bytes:3};
      set_placement_intent(&mut mandatory,b).unwrap();assert_ne!(mandatory.field(14).unwrap().flags&FIELD_CRITICAL,0);
      assert_eq!(placement_intent(&mandatory,3).unwrap(),Some(b));
  }
  #[test]fn locality_placement_rejects_oversize_and_mismatched_critical_flag(){
      let mut m=sample();set_placement_intent(&mut m,PlacementIntent{mode:PlacementMode::Prefer,numa_node:Some(1),max_bytes:4}).unwrap();
      assert!(placement_intent(&m,3).is_err());
      let mut m=sample();set_placement_intent(&mut m,PlacementIntent{mode:PlacementMode::Prefer,numa_node:Some(1),max_bytes:3}).unwrap();
      m.fields.iter_mut().find(|f|f.id==14).unwrap().flags|=FIELD_CRITICAL;assert!(placement_intent(&m,3).is_err());
  }
  #[test]fn locality_placement_result_round_trip_and_absence_is_unknown(){
      let mut m=Message::new(Header::new(MSG_RESPONSE,7,SCHEMA_BROKER_RESPONSE,1));
      let v=PlacementResult{outcome:PlacementOutcome::Fallback,applied_numa_node:None,reason:Some(PlacementReason::AllocatorUnavailable)};
      set_placement_result(&mut m,v).unwrap();assert_eq!(placement_result(&m).unwrap(),Some(v));
      let empty=Message::new(Header::new(MSG_RESPONSE,8,SCHEMA_BROKER_RESPONSE,1));assert_eq!(placement_result(&empty).unwrap(),None);
  }
  #[test]fn repeated_fields_require_explicit_flags(){let mut m=Message::new(Header::new(MSG_PING,1,0,0));m.push(Field::u8(77,1).repeated());m.push(Field::u8(77,2).repeated());assert!(encode(&m,Limits::default()).is_ok());}
  #[test]fn deterministic_malformed_corpus_never_panics(){
      use std::panic::{catch_unwind, AssertUnwindSafe};
      let seed = encode(&sample(), Limits::default()).unwrap();
      for cut in 0..seed.len() { let result = catch_unwind(AssertUnwindSafe(|| decode(&seed[..cut], Limits::default()))); assert!(result.is_ok(), "decoder panicked on truncation at {cut}"); }
      for index in 0..seed.len() { for bit in 0..8 { let mut mutated = seed.clone(); mutated[index] ^= 1 << bit; let result = catch_unwind(AssertUnwindSafe(|| decode(&mutated, Limits::default()))); assert!(result.is_ok(), "decoder panicked on byte {index}"); } }
  }
}
