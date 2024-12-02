// LemonHaze (Dylan) - 2024
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package scn3;

import java.io.InputStream;
import java.io.IOException;
import java.util.*;

import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;

import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

import ghidra.program.model.lang.LanguageCompilerSpecPair;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.flatapi.*;

public class SCN3Loader extends AbstractLibrarySupportLoader {
	@Override
	public String getName() {
		return "SCN3";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		if(reader.readAsciiString(0, 4).equals("SCN3")) {
			Msg.info(this, "Found SCN3 header");
			loadSpecs.add((new LoadSpec(this, 0, new LanguageCompilerSpecPair("SCN3:LE:32:SCN3", "default"), true)));
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		Memory mem = program.getMemory();
		
		int wholeSize = reader.readInt(0x4);
		int unkFlag = reader.readInt(0x8);
		int funcPtrOffs = reader.readInt(0xC);
		int dataSegmentOffs = reader.readInt(0x10);
		int lastBlockOffs = reader.readInt(0x14);
		int funcPtrOffs2 = reader.readInt(0x18);
		int unkOffs = reader.readInt(0x1C);
		int entrypointOffset = reader.readInt(0x20);
		
		// size of header = 0x30	
		int executableSize = wholeSize - 0x30 - (wholeSize - dataSegmentOffs);
		int dataSegmentSize = wholeSize - dataSegmentOffs;
		
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		try {
			MemoryBlock header = program.getMemory().createInitializedBlock(".header", addr, 0x30, (byte)0x00, monitor, false);
			header.setRead(false);
			header.setWrite(false);
			header.setExecute(false);
			
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x30);
			MemoryBlock code = program.getMemory().createInitializedBlock(".code", addr, executableSize, (byte)0x00, monitor, false);
			code.setRead(true);
			code.setWrite(false);
			code.setExecute(true);
			
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(dataSegmentOffs);
			MemoryBlock data = program.getMemory().createInitializedBlock(".data", addr, dataSegmentSize, (byte)0x00, monitor, false);
			data.setRead(true);
			data.setWrite(false);
			data.setExecute(false);
		} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException | CancelledException e) {
			log.appendException(e);
		}	
		byte romBytes[] = provider.readBytes(0, wholeSize);
		try {
			mem.setBytes(api.toAddr(0), romBytes);

			// create header fields
			createNamedString(api, 0x0, 4, "magic", log);
			createNamedDword(api, 0x4, "whole_size", log);
			createNamedDword(api, 0x8, "flag", log);
			createNamedDword(api, 0xC, "func_offs", log);
			createNamedDword(api, 0x10, "data_seg_offs", log);
			createNamedDword(api, 0x14, "last_block_offs", log);
			createNamedDword(api, 0x18, "func_offs2", log);
			createNamedDword(api, 0x1C, "unk_offs", log);
			createNamedDword(api, 0x20, "entrypoint_offs", log);
			createNamedDword(api, 0x24, "last_block_offs2", log);
			createNamedDword(api, 0x28, "reserved", log);
			createNamedDword(api, 0x2C, "reserved2", log);
			
			api.addEntryPoint(api.toAddr(entrypointOffset));
			api.disassemble(api.toAddr(entrypointOffset));
			api.createFunction(api.toAddr(entrypointOffset), "start_");
			
			if (funcPtrOffs > 0) {
				api.disassemble(api.toAddr(funcPtrOffs));
				api.createFunction(api.toAddr(funcPtrOffs), "fn1_");
			}

			if (funcPtrOffs2 > 0) {
				api.disassemble(api.toAddr(funcPtrOffs));
				api.createFunction(api.toAddr(funcPtrOffs), "fn2_");
			}
		} catch (MemoryAccessException e) {
			log.appendException(e);
		}
	}

	private static void createNamedString(FlatProgramAPI api, long address, int size, String name, MessageLog log)
	{
		try {
			api.createAsciiString(api.toAddr(address), size);
		} catch (Exception e) {
			log.appendException(e);
		}
		try {
			api.getCurrentProgram().getSymbolTable().createLabel(api.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
		
	}
	private static void createNamedDword(FlatProgramAPI api, long address, String name, MessageLog log)
	{
		try {
			api.createDWord(api.toAddr(address));
		} catch (Exception e) {
			log.appendException(e);
		}
		try {
			api.getCurrentProgram().getSymbolTable().createLabel(api.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}