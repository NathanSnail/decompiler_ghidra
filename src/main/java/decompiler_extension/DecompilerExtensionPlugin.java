package decompiler_extension;

import javax.swing.*;
import java.util.HashSet;
import java.util.regex.*;
import java.util.ArrayList;
import java.awt.Color;
import java.lang.IllegalArgumentException;
import java.lang.IllegalAccessException;
import java.util.Iterator;
import java.lang.reflect.Field;
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
	private Pattern regex;

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
		regex = Pattern.compile("if \\([^ ]+ == NULL\\) \\{([^ ]+) = \\(GameGlobal \\*\\)operator_new\\(0x1a0\\);");
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (!(loc instanceof DecompilerLocation)) { return; }
		// NOTE: This is in the event queue. Gotta go fast or do it in another thread.
		DecompileResults results = ((DecompilerLocation) loc).getDecompile();
		if (results == null) {
			return;
		}
		HighFunction hf = results.getHighFunction();
		// Msg.info(this, hf.getFunction().getName());
		// do stuff
		DecompileData data = controller.getDecompileData();
		// Msg.info(this, data);
		ClangTokenGroup tokens = data.getCCodeMarkup();
		Iterator<ClangToken> it = tokens.tokenIterator(true);
		Field field = null;
		try {
			field = ClangToken.class.getDeclaredField("syntax_type");
		} catch (Exception e) { }
		field.setAccessible(true);
		boolean did_something = false;
		String src_flat = "";
		ArrayList<Integer> indexes = new ArrayList();
		ArrayList<ClangToken> token_arr = new ArrayList();
		Integer index = -1;
		while (it.hasNext()) {
			index++;
			ClangToken next = it.next();
			token_arr.add(next);
			String text = next.getText();
			src_flat += text;
			for (int i = 0; i < text.length(); i++) {
				indexes.add(index);
			}
			if (text.equals("NULL")) {
				if (next.getSyntaxType() == ClangToken.CONST_COLOR) {
					continue;
				}
				try {
					field.set(next, ClangToken.CONST_COLOR);
					did_something = true;
				} catch (Exception e) { }
			}
		}
		did_something = true;
		Msg.info(this, src_flat);
		Matcher m = regex.matcher(src_flat);
		while (m.find()) {
			int start = m.start();
			int end = m.end();
			Msg.info(this, start);
			Msg.info(this, end);
			Msg.info(this, src_flat.substring(start, end));
			int start_index = indexes.get(start);
			int end_index = indexes.get(end);
			ClangTokenGroup start_group = (ClangTokenGroup)token_arr.get(start_index).Parent();
			ClangTokenGroup end_group = (ClangTokenGroup)token_arr.get(end_index).Parent();
			ClangTokenGroup containing_group = CommonAncestor(start_group, end_group);
			Field tok_field = null;
			try {
				tok_field = ClangTokenGroup.class.getDeclaredField("tokgroup");
			} catch (Exception e) { }
			try {
				tok_field.set(containing_group, new ArrayList());
			} catch (Exception e) { }
			containing_group.AddTokenGroup(new ClangToken(tokens, "uninlined", ClangToken.KEYWORD_COLOR));
			containing_group.AddTokenGroup(new ClangToken(tokens, " "));
			containing_group.AddTokenGroup(new ClangToken(tokens, "ConstructGameGlobal", ClangToken.GLOBAL_COLOR));
			containing_group.AddTokenGroup(new ClangToken(tokens, "(", ClangToken.DEFAULT_COLOR));
			containing_group.AddTokenGroup(new ClangToken(tokens, m.group(1)));
			containing_group.AddTokenGroup(new ClangToken(tokens, ")", ClangToken.DEFAULT_COLOR));
			containing_group.AddTokenGroup(new ClangToken(tokens, ";", ClangToken.DEFAULT_COLOR));
		}
		if (did_something) {
			controller.setDecompileData(data);
		}
		// tokens.setHighlight(Color.GREEN);
		// Msg.info(this, tokens);
		// controller.refreshDisplay(loc.getProgram(), currentLocation, null);
	}

	private ClangTokenGroup CommonAncestor(ClangTokenGroup a, ClangTokenGroup b) {
		HashSet<ClangTokenGroup> set = new HashSet();
		do {
			set.add(a);
			a = (ClangTokenGroup)a.Parent();
		} while (a != null);
		while (true) {
			if (set.contains(b)) {
				return b;
			}
			b = (ClangTokenGroup)b.Parent();
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
