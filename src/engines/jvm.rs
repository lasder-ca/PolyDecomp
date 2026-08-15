use super::{MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_MEMBER, MAX_ARCHIVE_TOTAL, Reader};
use std::fmt::Write as _;
use std::io::{Cursor, Read};
use zip::ZipArchive;

#[derive(Clone, Debug)]
enum Cp { Empty, Utf8(String), Class(u16), String(u16), Ref(u16,u16), NameType(u16,u16), Number(String) }

fn utf8(cp:&[Cp], i:u16)->Option<&str>{ match cp.get(i as usize)? { Cp::Utf8(s)=>Some(s), _=>None } }
fn class(cp:&[Cp], i:u16)->Option<String>{ match cp.get(i as usize)? { Cp::Class(n)=>utf8(cp,*n).map(|s|s.replace('/','.')), _=>None } }
fn cp_text(cp:&[Cp], i:u16)->String{
    match cp.get(i as usize){
        Some(Cp::Utf8(s))=>format!("{s:?}"), Some(Cp::Class(_))=>class(cp,i).unwrap_or_default(),
        Some(Cp::String(n))=>utf8(cp,*n).map_or_else(||format!("#{n}"),|s|format!("{s:?}")),
        Some(Cp::Number(s))=>s.clone(), Some(Cp::NameType(n,d))=>format!("{}:{}",utf8(cp,*n).unwrap_or("?"),utf8(cp,*d).unwrap_or("?")),
        Some(Cp::Ref(c,n))=>format!("{}.{}",class(cp,*c).unwrap_or_else(||"?".into()),cp_text(cp,*n)), _=>format!("#{i}")
    }
}
fn pool(r:&mut Reader<'_>)->Result<Vec<Cp>,String>{
    let count=r.be_u16()? as usize; if count==0{return Err("invalid constant pool".into())}
    let mut cp=vec![Cp::Empty]; let mut i=1;
    while i<count { let tag=r.u8()?; let v=match tag {
        1=>{let n=r.be_u16()? as usize; Cp::Utf8(String::from_utf8_lossy(r.take(n)?).into_owned())},
        3=>Cp::Number((r.be_u32()? as i32).to_string()), 4=>Cp::Number(f32::from_bits(r.be_u32()?).to_string()),
        5=>{let a=r.be_u32()? as u64;let b=r.be_u32()? as u64;cp.push(Cp::Number(((a<<32|b) as i64).to_string()));cp.push(Cp::Empty);i+=2;continue},
        6=>{let a=r.be_u32()? as u64;let b=r.be_u32()? as u64;cp.push(Cp::Number(f64::from_bits(a<<32|b).to_string()));cp.push(Cp::Empty);i+=2;continue},
        7=>Cp::Class(r.be_u16()?),8=>Cp::String(r.be_u16()?),9..=11=>Cp::Ref(r.be_u16()?,r.be_u16()?),12=>Cp::NameType(r.be_u16()?,r.be_u16()?),
        15=>{r.skip(3)?;Cp::Empty},16|19|20=>{r.skip(2)?;Cp::Empty},17|18=>{r.skip(4)?;Cp::Empty}, _=>return Err(format!("unsupported constant-pool tag {tag}"))}; cp.push(v);i+=1 }
    if cp.len()!=count{return Err("malformed constant pool".into())} Ok(cp)
}
fn skip_attrs(r:&mut Reader<'_>)->Result<(),String>{for _ in 0..r.be_u16()?{r.skip(2)?;let n=r.be_u32()? as usize;r.skip(n)?}Ok(())}
fn ty(d:&str,p:&mut usize)->String{let b=d.as_bytes();let mut a=0;while b.get(*p)==Some(&b'['){a+=1;*p+=1}let t=match b.get(*p){Some(b'V')=>"void".into(),Some(b'Z')=>"boolean".into(),Some(b'B')=>"byte".into(),Some(b'C')=>"char".into(),Some(b'S')=>"short".into(),Some(b'I')=>"int".into(),Some(b'J')=>"long".into(),Some(b'F')=>"float".into(),Some(b'D')=>"double".into(),Some(b'L')=>{*p+=1;let s=*p;while b.get(*p).is_some_and(|x|*x!=b';'){*p+=1}let v=d.get(s..*p).unwrap_or("Object").replace('/','.');format!("{v}")},_=>"Object".into()};*p+=1;format!("{t}{}","[]".repeat(a))}
fn method_desc(d:&str)->(Vec<String>,String){let mut p=usize::from(d.starts_with('('));let mut a=vec![];while d.as_bytes().get(p).is_some_and(|x|*x!=b')'){a.push(ty(d,&mut p))}if d.as_bytes().get(p)==Some(&b')'){p+=1}(a,ty(d,&mut p))}
fn mods(f:u16)->String{let mut v=vec![];if f&1!=0{v.push("public")}if f&2!=0{v.push("private")}if f&4!=0{v.push("protected")}if f&8!=0{v.push("static")}if f&16!=0{v.push("final")}if f&0x400!=0{v.push("abstract")}if v.is_empty(){String::new()}else{format!("{} ",v.join(" "))}}
fn opname(o:u8)->&'static str{match o{0x00=>"nop",0x01=>"aconst_null",0x02..=0x08=>"iconst",0x10=>"bipush",0x11=>"sipush",0x12..=0x14=>"ldc",0x15..=0x19=>"load",0x36..=0x3a=>"store",0x57=>"pop",0x59=>"dup",0x60=>"iadd",0x64=>"isub",0x68=>"imul",0x6c=>"idiv",0x84=>"iinc",0x99..=0xa6=>"if",0xa7=>"goto",0xac..=0xb1=>"return",0xb2=>"getstatic",0xb3=>"putstatic",0xb4=>"getfield",0xb5=>"putfield",0xb6=>"invokevirtual",0xb7=>"invokespecial",0xb8=>"invokestatic",0xb9=>"invokeinterface",0xba=>"invokedynamic",0xbb=>"new",0xbd=>"anewarray",0xbf=>"athrow",0xc0=>"checkcast",0xc1=>"instanceof",_=>"op"}}
fn oplen(o:u8)->usize{match o{0x10|0x12|0x15..=0x19|0x36..=0x3a=>2,0x11|0x13|0x14|0x84|0x99..=0xa8|0xb2..=0xb8|0xbb|0xbd|0xc0|0xc1|0xc6|0xc7=>3,0xb9|0xba|0xc8|0xc9=>5,0xc5=>4,_=>1}}
fn code_text(code:&[u8],cp:&[Cp])->String{let mut s=String::new();let mut p=0;while p<code.len(){let o=code[p];if matches!(o,0xaa|0xab|0xc4){let _=writeln!(s,"        // {p:04x}: {} (variable-length; raw tail follows)",opname(o));for (i,b) in code[p..].iter().take(64).enumerate(){let _=write!(s,"{}{:02x}",if i%16==0{"\n        //   "}else{" "},b)}s.push('\n');break}let n=oplen(o);if p+n>code.len(){break}let q=&code[p+1..p+n];let detail=if matches!(o,0x12){cp_text(cp,q[0] as u16)}else if matches!(o,0x13|0x14|0xb2..=0xb9|0xbb|0xbd|0xc0|0xc1)&&q.len()>=2{cp_text(cp,u16::from_be_bytes([q[0],q[1]]))}else{q.iter().map(|b|format!("{b:02x}")).collect::<Vec<_>>().join(" ")};let _=writeln!(s,"        // {p:04x}: {:<18} {detail}",opname(o));p+=n}s}

pub fn decompile_class(data:&[u8])->Result<String,String>{
    let mut r=Reader::new(data);if r.be_u32()?!=0xcafebabe{return Err("not a JVM class".into())}let _minor=r.be_u16()?;let major=r.be_u16()?;let cp=pool(&mut r)?;let access=r.be_u16()?;let this=r.be_u16()?;let sup=r.be_u16()?;let name=class(&cp,this).ok_or("invalid class name")?;let parent=if sup==0{None}else{class(&cp,sup)};let mut interfaces=[];
    let ic=r.be_u16()? as usize;let mut iv=Vec::with_capacity(ic);for _ in 0..ic{if let Some(x)=class(&cp,r.be_u16()?){iv.push(x)}}let simple=name.rsplit('.').next().unwrap_or(&name);let mut out=String::new();if let Some((pkg,_))=name.rsplit_once('.') {let _=writeln!(out,"package {pkg};\n")}let kind=if access&0x200!=0{"interface"}else if access&0x4000!=0{"enum"}else{"class"};let _=write!(out,"// PolyDecomp built-in JVM engine; class version {major}\n{}{kind} {simple}",mods(access));if kind=="class"{if let Some(p)=parent{if p!="java.lang.Object"{let _=write!(out," extends {p}")}}}if !iv.is_empty(){let _=write!(out," {} {}",if kind=="interface"{"extends"}else{"implements"},iv.join(", "))}out.push_str(" {\n");
    let fc=r.be_u16()?;for _ in 0..fc{let f=r.be_u16()?;let n=utf8(&cp,r.be_u16()?).unwrap_or("field").to_owned();let d=utf8(&cp,r.be_u16()?).unwrap_or("Ljava/lang/Object;").to_owned();skip_attrs(&mut r)?;let mut p=0;let _=writeln!(out,"    {}{} {n};",mods(f),ty(&d,&mut p))}
    let mc=r.be_u16()?;for _ in 0..mc{let f=r.be_u16()?;let n=utf8(&cp,r.be_u16()?).unwrap_or("method").to_owned();let d=utf8(&cp,r.be_u16()?).unwrap_or("()V").to_owned();let ac=r.be_u16()?;let mut body=None;let mut stack=0;let mut locals=0;for _ in 0..ac{let an=utf8(&cp,r.be_u16()?).unwrap_or("").to_owned();let len=r.be_u32()? as usize;if an=="Code"{let start=r.position();stack=r.be_u16()?;locals=r.be_u16()?;let cn=r.be_u32()? as usize;if cn>64*1024*1024{return Err("JVM method exceeds safety limit".into())}body=Some(r.take(cn)?.to_vec());let ex=r.be_u16()? as usize;r.skip(ex*8)?;skip_attrs(&mut r)?;let used=r.position()-start;if used<len{r.skip(len-used)?}}else{r.skip(len)?}}
        let (args,ret)=method_desc(&d);let params=args.iter().enumerate().map(|(i,t)|format!("{t} arg{i}")).collect::<Vec<_>>().join(", ");if n=="<clinit>"{out.push_str("\n    static {\n")}else if n=="<init>"{let _=writeln!(out,"\n    {}{simple}({params}) {{",mods(f))}else{let _=writeln!(out,"\n    {}{ret} {n}({params}) {{",mods(f))}if let Some(c)=body{let _=writeln!(out,"        // max_stack={stack}, max_locals={locals}");out.push_str(&code_text(&c,&cp))}else{out.push_str("        // abstract/native: no Code attribute\n")}out.push_str("    }\n")}
    skip_attrs(&mut r)?;out.push_str("}\n");Ok(out)
}

fn safe_name(n:&str)->String{n.replace('\\',"/").split('/').filter(|x|!x.is_empty()&&*x!="."&&*x!="..").collect::<Vec<_>>().join("/")}
pub fn decompile_jar(data:&[u8])->Result<Vec<(String,String)>,String>{let mut z=ZipArchive::new(Cursor::new(data)).map_err(|e|format!("invalid JAR: {e}"))?;if z.len()>MAX_ARCHIVE_ENTRIES{return Err("too many JAR entries".into())}let mut total=0;let mut out=vec![];for i in 0..z.len(){let mut e=z.by_index(i).map_err(|e|e.to_string())?;if e.is_dir()||!e.name().ends_with(".class"){continue}if e.size()>MAX_ARCHIVE_MEMBER{return Err("JAR member too large".into())}total+=e.size();if total>MAX_ARCHIVE_TOTAL{return Err("JAR expanded size too large".into())}let name=safe_name(e.name()).trim_end_matches(".class").to_owned()+".java";let mut b=vec![];e.read_to_end(&mut b).map_err(|e|e.to_string())?;let src=decompile_class(&b).unwrap_or_else(|x|format!("// class parse failed: {x}\n"));out.push((name,src))}if out.is_empty(){Err("JAR has no class files".into())}else{Ok(out)}}

#[cfg(test)]mod tests{use super::*;#[test]fn desc(){let(a,r)=method_desc("(ILjava/lang/String;[B)V");assert_eq!(a,["int","java.lang.String","byte[]"]);assert_eq!(r,"void")}#[test]fn names(){assert_eq!(opname(0xb6),"invokevirtual")}}
