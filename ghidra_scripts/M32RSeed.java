// Seed M32R (Aisin 09G927750 1MB) code: vector table pointers + function starts after 'jmp r14' (1FCE) / 'pop r14' returns
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
public class M32RSeed extends GhidraScript {
 boolean stub(Address a){ var i=getInstructionAt(a); if(i==null) return true; String mn=i.getMnemonicString(); return mn.equals("BRA")||mn.equals("JMP")||a.getOffset()<0x2000; }
 public void run() throws Exception {
  Memory m=currentProgram.getMemory(); int n=0,f=0;
  // vector table (u32 BE pointers into 0x80000..0xF0000) at 0x20080..0x20400
  for(long a=0x20080;a<0x20400;a+=4){ long p=m.getInt(toAddr(a))&0xffffffffL; if(p>=0x22000&&p<0xF0000&&(p&1)==0){ if(new DisassembleCommand(toAddr(p),null,true).applyTo(currentProgram,monitor)) n++; if(!stub(toAddr(p))&&getFunctionAt(toAddr(p))==null&&new CreateFunctionCmd(toAddr(p)).applyTo(currentProgram,monitor)) f++; } }
  // after every 'jmp r14' (+ optional nop) starts a new function if next is PUSH / ADDI SP
  for(long a=0x22000;a<0xF0000;a+=2){ if((m.getShort(toAddr(a))&0xffff)!=0x1fce) continue;
    long b=a+2; int h=m.getShort(toAddr(b))&0xffff; if(h==0x7000) { b+=2; h=m.getShort(toAddr(b))&0xffff; }
    boolean push=(h&0xf0ff)==0x207f; boolean addisp=(h&0xff00)==0x4f00;   // push Rx = st Rx,@-sp ; addi sp,#-n
    if(!(push||addisp)) continue;
    Address s=toAddr(b); if(getInstructionAt(s)==null) new DisassembleCommand(s,null,true).applyTo(currentProgram,monitor);
    if(getFunctionAt(s)==null&&new CreateFunctionCmd(s).applyTo(currentProgram,monitor)) f++; }
  // call targets (BL) until no new functions appear
  for(int pass=0;pass<8;pass++){ int add=0;
    java.util.TreeSet<Long> tl=new java.util.TreeSet<>();
    for(var ins:currentProgram.getListing().getInstructions(true)){ if(!ins.getMnemonicString().equals("BL")) continue;
      for(var fl:ins.getFlows()) tl.add(fl.getOffset()); }
    java.util.List<Address> tg=new java.util.ArrayList<>(); for(long v:tl) if(v>=0x2000&&v<0x100000) tg.add(toAddr(v));
    for(Address t:tg){ if(getFunctionAt(t)!=null) continue; if(getInstructionAt(t)==null) new DisassembleCommand(t,null,true).applyTo(currentProgram,monitor);
      if(stub(t)) continue;
      try { if(new CreateFunctionCmd(t).applyTo(currentProgram,monitor)) {add++; f++;} } catch(Exception e) { println("fail "+t+" "+e); } }
    println("pass "+pass+" +"+add); if(add==0) break; }
  println("seeded vec="+n+" functions="+f);
 }}
