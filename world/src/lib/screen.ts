// screen positions of creatures and the castle, written by the globe every frame.
// plain mutable map, read it inside requestAnimationFrame, not in render.
export interface ScreenPoint {
  x: number;
  y: number;
  visible: boolean;
}
export const screen = {
  creatures: new Map<string, ScreenPoint>(),
  castle: { x: 0, y: 0, visible: false } as ScreenPoint,
};
