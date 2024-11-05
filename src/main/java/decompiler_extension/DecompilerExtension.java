package decompiler_extension;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;

@PluginInfo(status = PluginStatus.UNSTABLE, packageName = ExamplesPluginPackage.NAME, category = PluginCategoryNames.EXAMPLES, shortDescription = "", description = "", servicesRequired = {
		DecompilerHighlightService.class })
public class DecompilerExtension extends ProgramPlugin {

	private DecompilerController controller;

	public DecompilerExtension(PluginTool tool) {
		super(tool, true, false);
	}

	@Override
	protected void init() {
		DecompilerProvider service = (DecompilerProvider) tool.getService(DecompilerHighlightService.class);
		controller = service.getController();
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (loc instanceof DecompilerLocation) {
			// NOTE: This is in the event queue. Gotta go fast or do it in another thread.
			HighFunction hf = ((DecompilerLocation) loc).getDecompile().getHighFunction();
			System.out.println("hf = " + hf);
			// do stuff
			controller.refreshDisplay(loc.getProgram(), currentLocation, null);
		}
	}

}
