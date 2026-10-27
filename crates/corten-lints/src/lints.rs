//! The lints. Each names the ledger row it backs. All are `Allow` by default:
//! `cargo corten check` turns them on with `-F`, so an in-source `allow`
//! cannot lower them.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rustc_errors::DiagDecorator;
use rustc_hir::def::Res;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::intravisit::{self, FnKind, Visitor};
use rustc_hir::{
    BlockCheckMode, Body, ClosureKind, CoroutineDesugaring, CoroutineKind, Expr, ExprKind, FnDecl,
    Item, ItemKind, LetStmt, PatKind, Stmt, StmtKind, UnsafeSource,
};
use rustc_lint::{
    LateContext, LateLintPass, LintContext, LintStore, declare_lint, declare_lint_pass,
};
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::{Span, Symbol};

/// Crates whose macros may expand to `unsafe` and whose types are trusted:
/// the standard library is part of the TCB (docs/tcb.md).
const STD_CRATES: &[&str] = &["std", "core", "alloc"];

fn emit(cx: &LateContext<'_>, lint: &'static rustc_lint::Lint, span: Span, msg: String) {
    cx.emit_span_lint(
        lint,
        span,
        DiagDecorator(|diag| {
            diag.primary_message(msg);
        }),
    );
}

fn crate_of(cx: &LateContext<'_>, def_id: DefId) -> Symbol {
    cx.tcx.crate_name(def_id.krate)
}

fn is_std(cx: &LateContext<'_>, def_id: DefId) -> bool {
    STD_CRATES.contains(&crate_of(cx, def_id).as_str())
}

/// The function a call or method call resolves to.
fn callee(cx: &LateContext<'_>, expr: &Expr<'_>) -> Option<DefId> {
    match expr.kind {
        ExprKind::Call(func, _) => match func.kind {
            ExprKind::Path(ref qpath) => match cx.qpath_res(qpath, func.hir_id) {
                Res::Def(_, def_id) => Some(def_id),
                _ => None,
            },
            _ => None,
        },
        ExprKind::MethodCall(..) => cx.typeck_results().type_dependent_def_id(expr.hir_id),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CWE-252

declare_lint! {
    /// CWE-252: every non-unit return value is must-use (spec 4.7). Fires on
    /// `f();` and `let _ = f();` when `f` returns anything but `()` or `!`,
    /// except a method returning a reference to its own receiver's type (a
    /// builder: `cmd.arg(x);`), which carries no status.
    pub CORTEN_MUST_USE_RETURN,
    Allow,
    "a non-unit return value is discarded"
}

declare_lint_pass!(MustUseReturn => [CORTEN_MUST_USE_RETURN]);

fn discarded_value(cx: &LateContext<'_>, expr: &Expr<'_>) {
    if !matches!(expr.kind, ExprKind::Call(..) | ExprKind::MethodCall(..))
        || expr.span.in_external_macro(cx.sess().source_map())
    {
        return;
    }
    let ty = cx.typeck_results().expr_ty(expr);
    if ty.is_unit() || ty.is_never() {
        return;
    }
    // A builder method returning a reference to its own receiver
    // (`cmd.arg(x);` returns `&mut Command`) reports no status: the value is
    // the object the caller already holds.
    if let ExprKind::MethodCall(_, receiver, ..) = expr.kind
        && ty.is_ref()
        && ty.peel_refs() == cx.typeck_results().expr_ty_adjusted(receiver).peel_refs()
    {
        return;
    }
    emit(
        cx,
        CORTEN_MUST_USE_RETURN,
        expr.span,
        format!("the `{ty}` this call returns is discarded (every non-unit return is must-use)"),
    );
}

impl<'tcx> LateLintPass<'tcx> for MustUseReturn {
    fn check_stmt(&mut self, cx: &LateContext<'tcx>, stmt: &'tcx Stmt<'tcx>) {
        if let StmtKind::Semi(expr) = stmt.kind {
            discarded_value(cx, expr);
        }
    }

    fn check_local(&mut self, cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) {
        if let (PatKind::Wild, Some(init)) = (local.pat.kind, local.init) {
            discarded_value(cx, init);
        }
    }
}

// ---------------------------------------------------------------------------
// CWE-683

declare_lint! {
    /// CWE-683: an exported function with two or more parameters of the same
    /// type can be called with them swapped. Corten requires labelled
    /// arguments on public functions (spec 4.2); in Rust the label is a
    /// distinct type per parameter (a newtype, or one struct of named fields).
    /// Private functions and trait implementations (the trait fixes their
    /// signature) are exempt.
    pub CORTEN_LABELLED_PARAMS,
    Allow,
    "several parameters share a type and need labels"
}

declare_lint_pass!(LabelledParams => [CORTEN_LABELLED_PARAMS]);

impl<'tcx> LateLintPass<'tcx> for LabelledParams {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        decl: &'tcx FnDecl<'tcx>,
        _: &'tcx Body<'tcx>,
        span: Span,
        def_id: LocalDefId,
    ) {
        if matches!(kind, FnKind::Closure) || span.from_expansion() {
            return;
        }
        if cx.tcx.trait_impl_of_assoc(def_id.to_def_id()).is_some()
            || !cx.effective_visibilities.is_exported(def_id)
        {
            return;
        }
        let sig = cx.tcx.fn_sig(def_id).instantiate_identity().skip_binder();
        let skip = usize::from(decl.implicit_self().has_implicit_self());
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for ty in sig.inputs().iter().skip(skip) {
            let ty = cx.tcx.erase_and_anonymize_regions(*ty);
            let n = seen.entry(ty.to_string()).or_insert(0);
            *n = n.saturating_add(1);
        }
        let shared: Vec<String> = seen
            .into_iter()
            .filter(|(_, n)| *n >= 2)
            .map(|(t, n)| format!("{n} × `{t}`"))
            .collect();
        if !shared.is_empty() {
            emit(
                cx,
                CORTEN_LABELLED_PARAMS,
                span,
                format!(
                    "parameters share a type ({}) and can be swapped; labelled arguments are required: give each a distinct type",
                    shared.join(", ")
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CWE-493, CWE-500, CWE-607

declare_lint! {
    /// CWE-493/500/607: a public static with interior mutability is a public
    /// mutable variable (`static mut` already needs `unsafe`).
    pub CORTEN_PUB_INTERIOR_MUT_STATIC,
    Allow,
    "a public static has interior mutability"
}

declare_lint_pass!(PubInteriorMutStatic => [CORTEN_PUB_INTERIOR_MUT_STATIC]);

impl<'tcx> LateLintPass<'tcx> for PubInteriorMutStatic {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if !matches!(item.kind, ItemKind::Static(..)) {
            return;
        }
        let def_id = item.owner_id.to_def_id();
        if !cx.tcx.visibility(def_id).is_public() {
            return;
        }
        let ty = cx
            .tcx
            .type_of(def_id)
            .instantiate_identity()
            .skip_normalization();
        if !ty.is_freeze(cx.tcx, cx.typing_env()) {
            emit(
                cx,
                CORTEN_PUB_INTERIOR_MUT_STATIC,
                item.span,
                format!(
                    "public static of type `{ty}` has interior mutability: anyone can change it"
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The dependency-macro bypass (docs/gates/phase-1.md)

declare_lint! {
    /// `unsafe` that a macro from outside the standard library puts into the
    /// checked crate. rustc's `unsafe_code` lint is not reported inside
    /// external macro expansions; this lint is.
    pub CORTEN_UNSAFE_FROM_MACRO,
    Allow,
    "a macro expands to `unsafe` in the checked crate",
    report_in_external_macro
}

declare_lint_pass!(UnsafeFromMacro => [CORTEN_UNSAFE_FROM_MACRO]);

fn foreign_macro(cx: &LateContext<'_>, span: Span) -> Option<String> {
    if !span.from_expansion() {
        return None;
    }
    let data = span.ctxt().outer_expn_data();
    let def = data.macro_def_id?;
    if is_std(cx, def) {
        return None;
    }
    Some(cx.tcx.def_path_str(def))
}

impl<'tcx> LateLintPass<'tcx> for UnsafeFromMacro {
    fn check_block(&mut self, cx: &LateContext<'tcx>, block: &'tcx rustc_hir::Block<'tcx>) {
        if block.rules != BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided) {
            return;
        }
        if let Some(mac) = foreign_macro(cx, block.span) {
            emit(
                cx,
                CORTEN_UNSAFE_FROM_MACRO,
                block.span,
                format!("`unsafe` block expanded from macro `{mac}`"),
            );
        }
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let is_unsafe = match item.kind {
            ItemKind::Impl(ref imp) => imp.of_trait.is_some_and(|t| t.safety.is_unsafe()),
            ItemKind::Fn { ref sig, .. } => sig.header.is_unsafe(),
            _ => false,
        };
        if !is_unsafe {
            return;
        }
        if let Some(mac) = foreign_macro(cx, item.span) {
            emit(
                cx,
                CORTEN_UNSAFE_FROM_MACRO,
                item.span,
                format!("`unsafe` item expanded from macro `{mac}`"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The `from_template` gap (docs/gates/phase-2.md)

declare_lint! {
    /// A sink's `from_template` called outside the `corten-std` macro that
    /// owns it. The macros check the template at compile time; a direct call
    /// with a hand-written `Template` is checked only when the program is
    /// built, so `cargo check` would accept it.
    pub CORTEN_DIRECT_TEMPLATE,
    Allow,
    "a sink's `from_template` is called directly",
    report_in_external_macro
}

declare_lint_pass!(DirectTemplate => [CORTEN_DIRECT_TEMPLATE]);

impl<'tcx> LateLintPass<'tcx> for DirectTemplate {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some(def_id) = callee(cx, expr) else {
            return;
        };
        if cx.tcx.item_name(def_id).as_str() != "from_template"
            || crate_of(cx, def_id).as_str() != "corten_std"
        {
            return;
        }
        // The crate's own macros call it; their expansion is trusted.
        let from_std_macro = expr.span.from_expansion()
            && expr
                .span
                .ctxt()
                .outer_expn_data()
                .macro_def_id
                .is_some_and(|m| crate_of(cx, m).as_str() == "corten_std");
        if !from_std_macro {
            emit(
                cx,
                CORTEN_DIRECT_TEMPLATE,
                expr.span,
                format!(
                    "`{}` called directly: build sink values with the corten-std macro, which checks the template",
                    cx.tcx.def_path_str(def_id)
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CWE-1322

declare_lint! {
    /// CWE-1322: a blocking call inside an async body (spec 4.8). The
    /// blocking effect is inferred: a standard-library primitive on the list
    /// below blocks, and so does a local function that calls one, directly or
    /// through other local functions. Calls into other crates are not
    /// followed.
    pub CORTEN_BLOCKING_IN_ASYNC,
    Allow,
    "a blocking call inside an async body"
}

/// Standard-library blocking primitives, as (type or module, function).
/// `fs`, `net` and `process` are listed whole.
const BLOCKING: &[(&str, &str)] = &[
    ("thread", "sleep"),
    ("thread", "park"),
    ("thread", "park_timeout"),
    ("JoinHandle", "join"),
    ("Mutex", "lock"),
    ("RwLock", "read"),
    ("RwLock", "write"),
    ("Condvar", "wait"),
    ("Condvar", "wait_while"),
    ("Condvar", "wait_timeout"),
    ("Condvar", "wait_timeout_while"),
    ("Barrier", "wait"),
    ("Receiver", "recv"),
    ("Receiver", "recv_timeout"),
    ("SyncSender", "send"),
    ("Stdin", "read_line"),
    ("Stdin", "lock"),
    ("fs", "*"),
    ("net", "*"),
    ("process", "*"),
];

fn is_blocking_primitive(cx: &LateContext<'_>, def_id: DefId) -> bool {
    if !is_std(cx, def_id) {
        // corten-std's filesystem capability performs blocking syscalls.
        let path = cx.get_def_path(def_id);
        return crate_of(cx, def_id).as_str() == "corten_std"
            && path.iter().any(|s| s.as_str() == "fs");
    }
    let path: Vec<String> = cx
        .get_def_path(def_id)
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect();
    let name = cx.tcx.item_name(def_id);
    let owner = cx
        .tcx
        .impl_of_assoc(def_id)
        .and_then(|imp| {
            cx.tcx
                .type_of(imp)
                .instantiate_identity()
                .skip_normalization()
                .ty_adt_def()
        })
        .map(|adt| cx.tcx.item_name(adt.did()).as_str().to_owned());
    BLOCKING.iter().any(|(scope, func)| {
        let scope_hit = owner.as_deref() == Some(*scope) || path.iter().any(|p| p == scope);
        scope_hit && (*func == "*" || name.as_str() == *func)
    })
}

#[derive(Default)]
pub struct BlockingInAsync {
    /// Local function -> (calls it makes, with their spans).
    calls: HashMap<LocalDefId, Vec<(Span, DefId)>>,
    /// Async bodies, by the function or block that owns them.
    async_bodies: Vec<LocalDefId>,
}

rustc_lint::impl_lint_pass!(BlockingInAsync => [CORTEN_BLOCKING_IN_ASYNC]);

struct CallCollector<'tcx> {
    typeck: &'tcx ty::TypeckResults<'tcx>,
    out: Vec<(Span, DefId)>,
}

impl<'tcx> Visitor<'tcx> for CallCollector<'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        let def = match expr.kind {
            ExprKind::Call(func, _) => match func.kind {
                ExprKind::Path(ref qpath) => match self.typeck.qpath_res(qpath, func.hir_id) {
                    Res::Def(_, def_id) => Some(def_id),
                    _ => None,
                },
                _ => None,
            },
            ExprKind::MethodCall(..) => self.typeck.type_dependent_def_id(expr.hir_id),
            _ => None,
        };
        if let Some(def_id) = def {
            self.out.push((expr.span, def_id));
        }
        intravisit::walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for BlockingInAsync {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        _: Span,
        def_id: LocalDefId,
    ) {
        let mut collector = CallCollector {
            typeck: cx.tcx.typeck(def_id),
            out: Vec::new(),
        };
        collector.visit_expr(body.value);
        self.calls.insert(def_id, collector.out);
    }

    fn check_expr(&mut self, _: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Closure(closure) = expr.kind
            && matches!(
                closure.kind,
                ClosureKind::Coroutine(CoroutineKind::Desugared(CoroutineDesugaring::Async, _))
            )
        {
            self.async_bodies.push(closure.def_id);
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        // Fixpoint: a local function blocks if it calls a blocking primitive
        // or a local function that blocks.
        let mut blocking: HashSet<LocalDefId> = HashSet::new();
        loop {
            let before = blocking.len();
            for (owner, calls) in &self.calls {
                if blocking.contains(owner) {
                    continue;
                }
                let blocks = calls.iter().any(|(_, callee)| {
                    is_blocking_primitive(cx, *callee)
                        || callee.as_local().is_some_and(|l| blocking.contains(&l))
                });
                if blocks {
                    blocking.insert(*owner);
                }
            }
            if blocking.len() == before {
                break;
            }
        }
        for body in &self.async_bodies {
            for (span, callee) in self.calls.get(body).into_iter().flatten() {
                let direct = is_blocking_primitive(cx, *callee);
                let transitive = callee.as_local().is_some_and(|l| blocking.contains(&l));
                if direct || transitive {
                    emit(
                        cx,
                        CORTEN_BLOCKING_IN_ASYNC,
                        *span,
                        format!(
                            "blocking call to `{}` inside an async body{}",
                            cx.tcx.def_path_str(*callee),
                            if direct {
                                ""
                            } else {
                                " (it blocks through a local function)"
                            }
                        ),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CWE-1091

declare_lint! {
    /// CWE-1091: a type with a destructor that can sit on an `Rc`/`Arc`
    /// cycle through interior mutability. A cycle is never freed, so the
    /// destructor never runs (spec 4.1). Decided on types, not values: a
    /// type that only ever forms trees is still reported; use `Weak` for the
    /// back edge.
    pub CORTEN_RC_CYCLE,
    Allow,
    "a type with a destructor can form an Rc/Arc cycle"
}

declare_lint_pass!(RcCycle => [CORTEN_RC_CYCLE]);

/// Interior-mutability wrappers: a cycle needs one to close after construction.
const CELLS: &[&str] = &[
    "Cell",
    "RefCell",
    "UnsafeCell",
    "OnceCell",
    "Mutex",
    "RwLock",
    "OnceLock",
];

struct CycleSearch<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    target: DefId,
    visited: BTreeSet<(String, bool, bool)>,
}

impl<'tcx> CycleSearch<'_, 'tcx> {
    /// Can `ty` reach `target` again, having passed a cell and a shared
    /// pointer on the way?
    fn reaches(&mut self, ty: Ty<'tcx>, cell: bool, shared: bool, depth: u32) -> bool {
        if depth > 32 {
            return false;
        }
        let key = (ty.to_string(), cell, shared);
        if !self.visited.insert(key) {
            return false;
        }
        let tcx: TyCtxt<'tcx> = self.cx.tcx;
        let next = depth.saturating_add(1);
        match ty.kind() {
            ty::Adt(adt, args) => {
                if adt.did() == self.target && cell && shared {
                    return true;
                }
                let name = tcx.item_name(adt.did());
                let name = name.as_str();
                let std = is_std(self.cx, adt.did());
                if std && name == "Weak" {
                    return false; // a weak edge does not own
                }
                let cell = cell || (std && CELLS.contains(&name));
                let shared = shared || (std && (name == "Rc" || name == "Arc"));
                if adt.did().is_local() {
                    adt.all_fields().any(|f| {
                        self.reaches(f.ty(tcx, args).skip_normalization(), cell, shared, next)
                    })
                } else {
                    // Outside the crate, follow the type arguments: what a
                    // container holds.
                    args.types().any(|t| self.reaches(t, cell, shared, next))
                }
            }
            ty::Tuple(tys) => tys.iter().any(|t| self.reaches(t, cell, shared, next)),
            ty::Array(t, _) | ty::Slice(t) => self.reaches(*t, cell, shared, next),
            _ => false,
        }
    }
}

impl<'tcx> LateLintPass<'tcx> for RcCycle {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if !matches!(item.kind, ItemKind::Struct(..) | ItemKind::Enum(..)) {
            return;
        }
        let did = item.owner_id.to_def_id();
        let adt = cx.tcx.adt_def(did);
        if !adt.has_dtor(cx.tcx) {
            return;
        }
        let ty = cx
            .tcx
            .type_of(did)
            .instantiate_identity()
            .skip_normalization();
        let mut search = CycleSearch {
            cx,
            target: did,
            visited: BTreeSet::new(),
        };
        let ty::Adt(_, args) = ty.kind() else { return };
        let found = adt
            .all_fields()
            .any(|f| search.reaches(f.ty(cx.tcx, args).skip_normalization(), false, false, 0));
        if found {
            emit(
                cx,
                CORTEN_RC_CYCLE,
                item.span,
                format!(
                    "`{}` has a destructor and can form an Rc/Arc cycle through interior mutability; the cycle is never freed and the destructor never runs (use Weak for the back edge)",
                    cx.tcx.def_path_str(did)
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------

/// Every lint, for `--print`-style listings and the checker's flags.
pub const ALL: &[&rustc_lint::Lint] = &[
    CORTEN_MUST_USE_RETURN,
    CORTEN_LABELLED_PARAMS,
    CORTEN_PUB_INTERIOR_MUT_STATIC,
    CORTEN_UNSAFE_FROM_MACRO,
    CORTEN_DIRECT_TEMPLATE,
    CORTEN_BLOCKING_IN_ASYNC,
    CORTEN_RC_CYCLE,
];

pub fn register(store: &mut LintStore) {
    store.register_lints(ALL);
    store.register_late_lint_pass(Box::new(|_| Box::new(MustUseReturn)));
    store.register_late_lint_pass(Box::new(|_| Box::new(LabelledParams)));
    store.register_late_lint_pass(Box::new(|_| Box::new(PubInteriorMutStatic)));
    store.register_late_lint_pass(Box::new(|_| Box::new(UnsafeFromMacro)));
    store.register_late_lint_pass(Box::new(|_| Box::new(DirectTemplate)));
    store.register_late_lint_pass(Box::new(|_| Box::new(BlockingInAsync::default())));
    store.register_late_lint_pass(Box::new(|_| Box::new(RcCycle)));
}
