// TODO write a description for this script
//@author
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.FunctionParameterFieldLocation;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableLocation;


import java.util.*;

public class SynthetizeFnParams extends GhidraScript {
    private DecompInterface decomplib;
    DecompileResults lastResults = null;
    Map<Varnode, Long> knownSrc = new HashMap<>();

    public void run() throws Exception {

        try {

            // access the decompiler
            decomplib = setUpDecompiler(currentProgram);

            Varnode v = getVarnodeLocation();

            if (v != null) {
                println("got it");
                println("Yeah");
                Set<PcodeOp> backwardSlice = DecompilerUtils.getBackwardSliceToPCodeOps(v);
                dataFlow(backwardSlice);

            } else if (currentLocation instanceof DecompilerLocation) {

                println("Decompiler location");
                DecompilerLocation decL = (DecompilerLocation) currentLocation;
                ClangToken token = decL.getToken();
                Varnode varnode = DecompilerUtils.getVarnodeRef(token);

                if (varnode != null) {
                    println("Yeah");
                    Set<PcodeOp> backwardSlice = DecompilerUtils.getBackwardSliceToPCodeOps(varnode);
                    dataFlow(backwardSlice);
                } else   {
                    println("null :-(");
                }
            }

            if(!knownSrc.keySet().isEmpty())    {
                for(Varnode n : knownSrc.keySet())  {
                    Long computedValue = knownSrc.get(n);
                    if(computedValue != null)   {
                        println(n.toString() + " has computed value " + computedValue.toString());
                    }
                    else    {
                        println("Could not concretize value of storage location " + n.toString());
                    }
                }
            }
        } finally {
            decomplib.dispose();
        }
    }


    /**
     * Some "INDIRECT" opcodes achieve nothing but stating an equivalence
     * @param op the related PcodeOp
     * @return true if the PcodeOp can be ignored
     */
    private boolean isUselessIndirect(PcodeOp op)   {

        if(op.getMnemonic().equals("INDIRECT"))   {

            // written like this because of a bug in equals
            return Arrays.stream(op.getInputs())
                    .anyMatch(x -> x.getOffset() == op.getOutput().getOffset() &&
                    x.getSize() == op.getOutput().getSize() &&
                    x.getAddress().equals(op.getOutput().getAddress()));
        }

        return false;
    }

    /**
     * Varnode.equals/hashcode aren't implemented correctly :-(
     * @param varnode key
     * @param value value
     */
    private void putWrapper(Varnode varnode, Long value)    {
        Varnode node = knownSrc
                .keySet()
                .stream()
                .filter(x -> x.getOffset() == varnode.getOffset() &&
                        x.getSize()        == varnode.getSize() &&
                        x.getAddress().equals(varnode.getAddress()))
                .findFirst().orElse(varnode);

        knownSrc.put(node, value);
    }

    /**
     * Varnode.equals/hashcode aren't implemented correctly :-(
     * @param varnode key
     */
    private Optional<Long> getWrapper(Varnode varnode)    {
        Varnode node = knownSrc
                .keySet()
                .stream()
                .filter(x -> x.getOffset() == varnode.getOffset() &&
                        x.getSize()        == varnode.getSize() &&
                        x.getAddress().equals(varnode.getAddress()))
                .findFirst().orElse(varnode);

        return Optional.ofNullable(knownSrc.get(node));
    }

    /**
     * Computes statically the value contained in a register
     * @param varnode raw abstraction around opcodes and mnemonics
     * @return
     */
    private Long getConcreteValue(Varnode varnode)   {

        if(knownSrc.containsKey(varnode))   {
            return knownSrc.get(varnode);
        }

        assert(varnode.getAddress().getAddressSpace().getName().equals("const"));
        return varnode.getOffset();
    }

    /**
     * static computation of arithmetic operations in a given PcodeOp
     * @param op Abstraction around an assembly operation
     * @return the result of the computation
     */
    private Optional<Long> tryCompute(PcodeOp op)    {

        switch(op.getMnemonic())    {

            case "COPY": {
                long value = op.getInput(0).getOffset();
                assert (op.getInput(0).getAddress().getAddressSpace().getName().equals("const"));
                assert (op.getNumInputs() == 1);
                return Optional.of(value);
            }

            case "CAST": {
                long value = op.getInput(0).getOffset();
                assert (op.getInput(0).getAddress().getAddressSpace().getName().equals("const"));
                assert (op.getNumInputs() == 1);
                return Optional.of(value);
            }

            case "LOAD":{
                long value = op.getInput(0).getOffset();
                assert (op.getInput(0).getAddress().getAddressSpace().getName().equals("const"));
                return Optional.of(value);
            }

            case "INT_XOR": {
                assert (op.getNumInputs() == 2);
                Long value1 = getConcreteValue(op.getInput(0));
                Long value2 = getConcreteValue(op.getInput(1));
                return Optional.of(value1 ^ value2);
            }

            case "INT_SUB": {
                assert (op.getNumInputs() == 2);
                Long value1 = getConcreteValue(op.getInput(0));
                Long value2 = getConcreteValue(op.getInput(1));
                return Optional.of(value1 - value2); // underflow
            }

            case "INT_ADD": {
                assert (op.getNumInputs() == 2);
                Long value1 = getConcreteValue(op.getInput(0));
                Long value2 = getConcreteValue(op.getInput(1));
                return Optional.of(value1 + value2); //improve with check for overflow
            }

            case "INT_AND": {
                assert (op.getNumInputs() == 2);
                Long value1 = getConcreteValue(op.getInput(0));
                Long value2 = getConcreteValue(op.getInput(1));
                return Optional.of(value1 & value2); //improve with check for overflow
            }

            case "INT_2COMP": {
                Long value1 = getConcreteValue(op.getInput(0));
                return Optional.of(~value1-1); //improve with check for overflow
            }

            case "INT_ZEXT": {
                Long value1 = getConcreteValue(op.getInput(0));
                return Optional.of(value1); //improve with check for overflow
            }

            case "INDIRECT":
                // INDIRECT is a "probable" copy from one of the inputs, to the output

                Optional<Varnode> nodeValue = Arrays
                        .stream(op.getInputs())
                        .filter(x -> !x.getAddress().getAddressSpace().getName().equals("const"))
                        .findFirst();
                Varnode node = nodeValue.orElseThrow(RuntimeException::new);
                return getWrapper(node);

            default:
                println("Got unknown operation : " + op.toString());
                return Optional.empty();
        }
    }

    /**
     * tracks all the successive operations that contribute to the
     * actual value of the variable selected by the user.
     * @param backSlice
     */
    private void dataFlow(Set<PcodeOp> backSlice)   {
        List<PcodeOp> sorted = new ArrayList<>(backSlice);

        sorted.sort((x,y)->{
            if(x.getSeqnum().getOrder() < y.getSeqnum().getOrder()) return -1;
            if(y.getSeqnum().getOrder() == y.getSeqnum().getOrder()) return 0;
            return 1;
        });

        // todo: forward dataflow to detect futur-constant state
        for(PcodeOp vn : sorted)  {
            println(vn.getSeqnum() +  vn.toString());

            if(isUselessIndirect(vn))   {
                println("Skipping");
                continue;
            }

            if(knownSrc.containsKey(vn.getOutput()))    {
                Long currentValue = knownSrc.get(vn.getOutput());
                putWrapper(vn.getOutput(), tryCompute(vn).orElse(currentValue));
            }
            else    {
                Long value = tryCompute(vn).orElse(null);
                putWrapper(vn.getOutput(), value);
            }
        }

        println("Done");
    }


    //----------------------------------------------------------------
    // Boilerplate code to access the decompiler's output.

    /**
     * Try to locate the Varnode that represents the variable in the listing or
     * decompiler. In the decompiler this could be a local/parameter at any
     * point in the decompiler. In the listing, it must be a parameter variable.
     *
     * @return
     */
    private Varnode getVarnodeLocation() {
        Varnode var;

        if (currentLocation instanceof DecompilerLocation) {
            DecompilerLocation dloc;

            // get the Varnode under the cursor
            dloc = (DecompilerLocation) currentLocation;
            ClangToken tokenAtCursor = dloc.getToken();
            var = DecompilerUtils.getVarnodeRef(tokenAtCursor);

            if (tokenAtCursor == null) {
                println(
                        "****   please put the cursor on a variable in the decompiler!");
                return null;
            }
            lastResults = dloc.getDecompile();
        } else {
            // if we don't have one, make one, and map variable to a varnode
            HighSymbol highVar =
                    computeVariableLocation(currentProgram, currentLocation);
            if (highVar != null) {
                var = highVar.getHighVariable().getRepresentative();
            } else {
                return null;
            }
        }
        return var;
    }

    public DecompileResults decompileFunction(Function f,
                                              DecompInterface decompInterface) {
        // don't decompile the function again if it was the same as the last one
        lastResults = decompInterface.decompileFunction(
                f, decompInterface.getOptions().getDefaultTimeout(), monitor);

        return lastResults;
    }

    private HighSymbol computeVariableLocation(Program currProgram,
                                               ProgramLocation location) {
        HighSymbol highVar = null;
        Address storageAddress = null;

        // make sure what we are over can be mapped to decompiler
        // param, local, etc...

        if (location instanceof VariableLocation) {
            VariableLocation varLoc = (VariableLocation) location;
            storageAddress = varLoc.getVariable().getMinAddress();
        } else if (location instanceof FunctionParameterFieldLocation) {
            FunctionParameterFieldLocation funcPFL =
                    (FunctionParameterFieldLocation) location;
            storageAddress = funcPFL.getParameter().getMinAddress();
        } else if (location instanceof OperandFieldLocation) {

            OperandFieldLocation opLoc = (OperandFieldLocation) location;
            int opindex = opLoc.getOperandIndex();

            if (opindex >= 0) {
                Instruction instr =
                        currProgram.getListing().getInstructionAt(opLoc.getAddress());
                if (instr != null) {
                    Register reg = instr.getRegister(opindex);
                    if (reg != null) {
                        storageAddress = reg.getAddress();
                    }
                }
            }
        }

        if (storageAddress == null) {
            return null;
        }

        Address addr = currentLocation.getAddress();
        if (addr == null) {
            return null;
        }

        Function f = currProgram.getFunctionManager().getFunctionContaining(addr);
        if (f == null) {
            return null;
        }

        DecompileResults results = decompileFunction(f, decomplib);

        HighFunction hf = results.getHighFunction();
        if (hf == null) {
            return null;
        }

        // try to map the variable
        highVar =
                hf.getMappedSymbol(storageAddress, f.getEntryPoint().subtractWrap(1L));
        if (highVar == null) {
            highVar = hf.getMappedSymbol(storageAddress, null);
        }
        if (highVar == null) {
            highVar = hf.getMappedSymbol(storageAddress, f.getEntryPoint());
        }

        if (highVar != null) {
            // fixupParams(results, location.getAddress());
        }

        return highVar;
    }

    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();
        OptionsService service = state.getTool().getService(OptionsService.class);
        if (service != null) {
            ToolOptions opt = service.getOptions("Decompiler");
            options.grabFromToolAndProgram(null, opt, program);
        }
        decompInterface.setOptions(options);

        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        decompInterface.openProgram(program);

        return decompInterface;
    }
}
