package decompiler_extension;

import javax.swing.*;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
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
import ghidra.util.Msg;
import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import java.awt.event.KeyEvent;
import generic.theme.GIcon;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Decompiler Extension Hello",
	description = "Sample plugin to demonstrate services and action enablement, hello world.",
	servicesRequired = { DecompilerHighlightService.class }
)
//@formatter:on
public class DecompilerExtensionPlugin extends ProgramPlugin {
	private DockingAction programAction;
	private DecompilerController controller;

	/**
	  * Constructor
	  */
	public DecompilerExtensionPlugin(PluginTool tool) {
		super(tool);

		programAction = new DockingAction("Hello World", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "Wah");
			}
		};
		// Enable the action - by default actions are disabled.
		programAction.setEnabled(true);

		// Put the action in the global "View" menu.
		programAction.setMenuBarData(new MenuData(new String[] { "View", "Hello World" }));

		// Add the action to the tool.
		tool.addAction(programAction);

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
			Msg.info(this, loc);
			DecompileResults results = ((DecompilerLocation) loc).getDecompile();
			if (results == null) {
				return;
			}
			HighFunction hf = results.getHighFunction();
			Msg.info(this, hf.getFunction().getName());
			// do stuff
			DecompileData data = controller.getDecompileData();
			Msg.info(this, data);
			ClangTokenGroup tokens = data.getCCodeMarkup();
			Msg.info(this, tokens);
			controller.refreshDisplay(loc.getProgram(), currentLocation, null);
		}
	}


	/**
	 * If your plugin maintains configuration state, you must save that state information
	 * to the SaveState object in this method.  For example, the Code Browser can be configured
	 * to show fields in different colors.  This is the method where that type
	 * information is saved.
	 */
	@Override
	public void writeConfigState(SaveState saveState) {
	}

	/**
	 * If your plugin maintains configuration state, this is where you read it
	 * back in.
	 */
	@Override
	public void readConfigState(SaveState saveState) {
	}
}
