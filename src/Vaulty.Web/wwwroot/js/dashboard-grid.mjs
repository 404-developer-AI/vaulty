// The grid of the dashboard designer. This script only proposes places: it turns pointer and key
// input into columns and rows and asks the server, which places the tile with the one placement algorithm of Vaulty
// (DashboardGrid) and renders every position. Dragging moves the tile under the pointer; the other tiles move as the server
// answers. No library: pointer events on a CSS grid.

const ROW = 56;
const GAP = 12;
const COLUMNS = 12;
const DRAG_THRESHOLD = 4;

export function attach(canvas, palette, dotnet) {
  let drag = null;

  function grid() {
    return canvas.querySelector(".vy-dash-grid");
  }

  function cellSize() {
    const rect = grid().getBoundingClientRect();
    return { rect, column: (rect.width + GAP) / COLUMNS, row: ROW + GAP };
  }

  function tileRect(element) {
    return {
      x: Number(element.dataset.x), y: Number(element.dataset.y),
      w: Number(element.dataset.w), h: Number(element.dataset.h)
    };
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function onPointerDown(event) {
    if (event.button !== 0) {
      return;
    }

    const element = event.target.closest("[data-tile-id]");
    if (!element || !canvas.contains(element)) {
      return;
    }

    const resizing = event.target.closest("[data-resize]") !== null;
    drag = {
      element, id: element.dataset.tileId, resizing, start: tileRect(element), startX: event.clientX, startY: event.clientY,
      target: tileRect(element), moved: false, pointerId: event.pointerId
    };
    element.setPointerCapture(event.pointerId);
    element.focus({ preventScroll: true });
    event.preventDefault();
  }

  function onPointerMove(event) {
    if (!drag || event.pointerId !== drag.pointerId) {
      return;
    }

    const dx = event.clientX - drag.startX;
    const dy = event.clientY - drag.startY;
    if (!drag.moved && Math.abs(dx) < DRAG_THRESHOLD && Math.abs(dy) < DRAG_THRESHOLD) {
      return;
    }

    if (!drag.moved) {
      drag.moved = true;
      drag.element.classList.add("dragging");
    }

    const { column, row } = cellSize();
    const start = drag.start;
    let target;
    if (drag.resizing) {
      const w = clamp(Math.round(start.w + dx / column), 1, COLUMNS - start.x);
      const h = Math.max(1, Math.round(start.h + dy / row));
      target = { x: start.x, y: start.y, w, h };
    } else {
      drag.element.style.transform = `translate(${dx}px, ${dy}px)`;
      const x = clamp(Math.round(start.x + dx / column), 0, COLUMNS - start.w);
      const y = Math.max(0, Math.round(start.y + dy / row));
      target = { x, y, w: start.w, h: start.h };
    }

    if (target.x !== drag.target.x || target.y !== drag.target.y || target.w !== drag.target.w || target.h !== drag.target.h) {
      drag.target = target;
      dotnet.invokeMethodAsync("PreviewPlace", drag.id, target.x, target.y, target.w, target.h, drag.resizing).catch(() => { });
    }
  }

  async function onPointerUp(event) {
    if (!drag || event.pointerId !== drag.pointerId) {
      return;
    }

    const current = drag;
    drag = null;
    try {
      current.element.releasePointerCapture(current.pointerId);
    } catch {
      // The element may already be gone after a render.
    }

    try {
      if (!current.moved) {
        await dotnet.invokeMethodAsync("SelectTile", current.id);
      } else {
        const t = current.target;
        await dotnet.invokeMethodAsync("CommitPlace", current.id, t.x, t.y, t.w, t.h);
      }
    } catch {
      // The circuit reports its own problems; the tile goes back to where the server has it.
    } finally {
      current.element.style.transform = "";
      current.element.classList.remove("dragging");
    }
  }

  function onPointerCancel(event) {
    if (!drag || event.pointerId !== drag.pointerId) {
      return;
    }

    drag.element.style.transform = "";
    drag.element.classList.remove("dragging");
    drag = null;
    dotnet.invokeMethodAsync("CancelPlace").catch(() => { });
  }

  function onKeyDown(event) {
    const element = event.target.closest("[data-tile-id]");
    if (!element || !canvas.contains(element)) {
      return;
    }

    const moves = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    if (moves[event.key]) {
      event.preventDefault();
      const [dx, dy] = moves[event.key];
      dotnet.invokeMethodAsync("KeyPlace", element.dataset.tileId, dx, dy, event.shiftKey).catch(() => { });
    } else if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      dotnet.invokeMethodAsync("RemoveTile", element.dataset.tileId).catch(() => { });
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      dotnet.invokeMethodAsync("SelectTile", element.dataset.tileId).catch(() => { });
    }
  }

  function inField(target) {
    return target instanceof HTMLElement && (target.isContentEditable || target.closest("input, textarea, select, [contenteditable]") !== null);
  }

  function onDocumentKeyDown(event) {
    if (!(event.ctrlKey || event.metaKey) || inField(event.target)) {
      return;
    }

    const key = event.key.toLowerCase();
    if (key === "z" && !event.shiftKey) {
      event.preventDefault();
      dotnet.invokeMethodAsync("Undo").catch(() => { });
    } else if (key === "y" || (key === "z" && event.shiftKey)) {
      event.preventDefault();
      dotnet.invokeMethodAsync("Redo").catch(() => { });
    }
  }

  // A tile type dragged from the palette onto the grid lands on the cell under the pointer.
  function onDragStart(event) {
    const item = event.target.closest("[data-tile-type]");
    if (!item) {
      return;
    }

    event.dataTransfer.setData("application/x-vaulty-tile", item.dataset.tileType);
    event.dataTransfer.effectAllowed = "copy";
  }

  function onDragOver(event) {
    if (event.dataTransfer.types.includes("application/x-vaulty-tile")) {
      event.preventDefault();
      event.dataTransfer.dropEffect = "copy";
    }
  }

  function onDrop(event) {
    const type = event.dataTransfer.getData("application/x-vaulty-tile");
    if (!type) {
      return;
    }

    event.preventDefault();
    const { rect, column, row } = cellSize();
    const x = clamp(Math.floor((event.clientX - rect.left) / column), 0, COLUMNS - 1);
    const y = Math.max(0, Math.floor((event.clientY - rect.top) / row));
    dotnet.invokeMethodAsync("DropType", type, x, y).catch(() => { });
  }

  canvas.addEventListener("pointerdown", onPointerDown);
  canvas.addEventListener("pointermove", onPointerMove);
  canvas.addEventListener("pointerup", onPointerUp);
  canvas.addEventListener("pointercancel", onPointerCancel);
  canvas.addEventListener("keydown", onKeyDown);
  canvas.addEventListener("dragover", onDragOver);
  canvas.addEventListener("drop", onDrop);
  palette?.addEventListener("dragstart", onDragStart);
  document.addEventListener("keydown", onDocumentKeyDown);

  return {
    dispose() {
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerup", onPointerUp);
      canvas.removeEventListener("pointercancel", onPointerCancel);
      canvas.removeEventListener("keydown", onKeyDown);
      canvas.removeEventListener("dragover", onDragOver);
      canvas.removeEventListener("drop", onDrop);
      palette?.removeEventListener("dragstart", onDragStart);
      document.removeEventListener("keydown", onDocumentKeyDown);
    }
  };
}
