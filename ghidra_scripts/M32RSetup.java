// Aisin 09G927750 (M32R/ECU): RAM/SFR block + R12 = 0x80C000 global base
import ghidra.app.script.GhidraScript;
import java.math.BigInteger;
public class M32RSetup extends GhidraScript { public void run() throws Exception {
  var mem=currentProgram.getMemory();
  if(mem.getBlock(toAddr(0x800000))==null){ var b=mem.createUninitializedBlock("SFR_RAM",toAddr(0x800000),0x20000,false); b.setRead(true); b.setWrite(true); b.setVolatile(false); }
  var r12=currentProgram.getRegister("R12");
  currentProgram.getProgramContext().setValue(r12,toAddr(0),toAddr(0xFFFFF),BigInteger.valueOf(0x80C000));
  println("setup done");
}}
