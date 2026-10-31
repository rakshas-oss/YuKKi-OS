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
    let expected=match f.wire_type { WireType::U8|WireType::Bool=>Some(1),WireType::U16=>Some(2),WireType::U32|WireType::F32=>Some(4),WireType::U64|WireType::I64|WireType::F64=>Some(8),WireType::Uuid=>Some(16),_=>None };
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
    } Ok(())
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
    let mut fields=Vec::new();let mut p=HEADER_LEN;
    while p<b.len(){if fields.len()>=limits.max_fields{return Err(Error::TooManyFields)}if b.len()-p<TLV_HEADER_LEN{return Err(Error::Truncated("TLV header"))}
        let id=u16::from_be_bytes(b[p..p+2].try_into().unwrap());let wt=WireType::try_from(b[p+2])?;let ff=b[p+3];
        if ff & !KNOWN_FIELD_FLAGS!=0{return Err(Error::InvalidFieldFlags(ff))}
        let n=u32::from_be_bytes(b[p+4..p+8].try_into().unwrap()) as usize;p+=TLV_HEADER_LEN;
        let end=p.checked_add(n).ok_or(Error::LengthMismatch)?;if end>b.len(){return Err(Error::Truncated("TLV value"))}
        fields.push(Field{id,wire_type:wt,flags:ff,value:b[p..end].to_vec()});p=end;
    }
    validate_duplicates(&fields)?;for f in &fields{validate_value(f)?}
    Ok(Message{header:Header{major,minor,message_type,flags,request_id,schema_id,schema_version},fields})
}
pub fn validate_known_fields(m:&Message,known:&[(u16,WireType,bool)])->Result<(),Error>{
    for f in &m.fields {if let Some((_,expected,_))=known.iter().find(|(id,_,_)|*id==f.id){if f.wire_type!=*expected{return Err(Error::WrongWireType{field_id:f.id,expected:*expected,actual:f.wire_type})}}
        else if f.flags&FIELD_CRITICAL!=0{return Err(Error::UnknownCriticalField(f.id))}}
    for (id,_,required) in known{if *required&&m.field(*id).is_none(){return Err(Error::MissingField(*id))}}Ok(())
}

pub mod request_field {pub const TASK_ID:u16=1;pub const SOURCE:u16=2;pub const DESTINATION:u16=3;pub const KIND:u16=4;pub const PRIORITY:u16=5;pub const TIMEOUT_MS:u16=6;pub const PAYLOAD:u16=7;pub const IDEMPOTENCY_KEY:u16=8;pub const DEADLINE_UNIX_NS:u16=9;}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct BrokerRequest {pub task_id:String,pub source:String,pub destination:String,pub kind:String,pub priority:u8,pub timeout_ms:u32,pub payload:Vec<u8>,pub idempotency_key:Option<[u8;16]>,pub deadline_unix_ns:Option<u64>}
impl BrokerRequest {
    pub fn to_message(&self,request_id:u64)->Message{let mut m=Message::new(Header::new(MSG_REQUEST,request_id,SCHEMA_BROKER_REQUEST,1));
        m.push(Field::utf8(1,&self.task_id).critical());m.push(Field::utf8(2,&self.source).critical());m.push(Field::utf8(3,&self.destination).critical());m.push(Field::utf8(4,&self.kind).critical());
        m.push(Field::u8(5,self.priority).critical());m.push(Field::u32(6,self.timeout_ms).critical());m.push(Field::bytes(7,&self.payload).critical());
        if let Some(v)=self.idempotency_key{m.push(Field::uuid(8,v))}if let Some(v)=self.deadline_unix_ns{m.push(Field::u64(9,v))}m}
    pub fn from_message(m:&Message)->Result<Self,Error>{
        if m.header.message_type!=MSG_REQUEST||m.header.schema_id!=SCHEMA_BROKER_REQUEST{return Err(Error::InvalidValue("not a BrokerRequest"))}
        let schema=[(1,WireType::Utf8,true),(2,WireType::Utf8,true),(3,WireType::Utf8,true),(4,WireType::Utf8,true),(5,WireType::U8,true),(6,WireType::U32,true),(7,WireType::Bytes,true),(8,WireType::Uuid,false),(9,WireType::U64,false)];
        validate_known_fields(m,&schema)?;
        let s=|id:u16|->Result<String,Error>{Ok(std::str::from_utf8(&m.field(id).unwrap().value).map_err(|_|Error::InvalidUtf8(id))?.to_owned())};
        let task_id=s(1)?;let source=s(2)?;let destination=s(3)?;let kind=s(4)?;
        for (name,v) in [("task_id",&task_id),("source",&source),("destination",&destination),("kind",&kind)]{if v.trim().is_empty(){return Err(Error::InvalidValue(name))}}
        let timeout_ms=u32::from_be_bytes(m.field(6).unwrap().value[..4].try_into().unwrap());if timeout_ms==0{return Err(Error::InvalidValue("timeout_ms must be nonzero"))}
        Ok(Self{task_id,source,destination,kind,priority:m.field(5).unwrap().value[0],timeout_ms,payload:m.field(7).unwrap().value.clone(),
            idempotency_key:m.field(8).map(|f|f.value.as_slice().try_into().unwrap()),deadline_unix_ns:m.field(9).map(|f|u64::from_be_bytes(f.value[..8].try_into().unwrap()))})
    }
}

#[cfg(test)]
mod tests {
 use super::*;
 fn sample()->Message{BrokerRequest{task_id:"t-1".into(),source:"yukki".into(),destination:"broker".into(),kind:"inference".into(),priority:4,timeout_ms:5000,payload:vec![0,1,255],idempotency_key:None,deadline_unix_ns:Some(42)}.to_message(0x0102030405060708)}
 #[test]fn round_trip_and_endian(){let m=sample();let b=encode(&m,Limits::default()).unwrap();assert_eq!(&b[4..8],b"BRK2");assert_eq!(&b[16..24],&0x0102030405060708u64.to_be_bytes());assert_eq!(decode(&b,Limits::default()).unwrap(),m)}
 #[test]fn request_schema_round_trip(){let m=sample();let r=BrokerRequest::from_message(&m).unwrap();assert_eq!(r.task_id,"t-1");assert_eq!(r.payload,vec![0,1,255])}
 #[test]fn rejects_truncation_and_trailing_bytes(){let mut b=encode(&sample(),Limits::default()).unwrap();b.pop();assert!(matches!(decode(&b,Limits::default()),Err(Error::Truncated(_))));b=encode(&sample(),Limits::default()).unwrap();b.push(0);assert_eq!(decode(&b,Limits::default()),Err(Error::TrailingBytes))}
 #[test]fn rejects_bad_magic_reserved_and_flags(){let mut b=encode(&sample(),Limits::default()).unwrap();b[4]=b'X';assert_eq!(decode(&b,Limits::default()),Err(Error::BadMagic));b=encode(&sample(),Limits::default()).unwrap();b[30]=1;assert_eq!(decode(&b,Limits::default()),Err(Error::ReservedNonZero))}
 #[test]fn rejects_duplicate_and_invalid_utf8(){let mut m=sample();m.push(Field::utf8(1,"dup"));assert_eq!(encode(&m,Limits::default()),Err(Error::DuplicateSingularField(1)));m=sample();m.fields[0].value=vec![255];assert_eq!(encode(&m,Limits::default()),Err(Error::InvalidUtf8(1)))}
 #[test]fn rejects_unknown_critical_but_preserves_optional(){let mut m=sample();m.push(Field::u8(99,1));assert!(validate_known_fields(&m,&[(1,WireType::Utf8,true)]).is_ok());m.fields.last_mut().unwrap().flags|=FIELD_CRITICAL;assert_eq!(validate_known_fields(&m,&[(1,WireType::Utf8,true)]),Err(Error::UnknownCriticalField(99)))}
 #[test]fn rejects_limits_and_zero_timeout(){let b=encode(&sample(),Limits::default()).unwrap();let mut l=Limits::default();l.max_frame_bytes=32;assert!(matches!(decode(&b,l),Err(Error::FrameTooLarge(_))));let mut m=sample();m.field(6);m.fields.iter_mut().find(|f|f.id==6).unwrap().value=0u32.to_be_bytes().to_vec();assert_eq!(BrokerRequest::from_message(&m),Err(Error::InvalidValue("timeout_ms must be nonzero")))}
 #[test]fn repeated_fields_require_explicit_flags(){let mut m=Message::new(Header::new(MSG_PING,1,0,0));m.push(Field::u8(77,1).repeated());m.push(Field::u8(77,2).repeated());assert!(encode(&m,Limits::default()).is_ok())}
}
