import { create } from "zustand";
export type Subview = "overview" | "replay" | "details" | "dossier";
interface View {
  surface: "none" | "activity" | "creature";
  subview: Subview;
  selectedAttacker: string | null;
  selectedSession: string | null;
  origin: "map" | "activity";
  feedScroll: number;
  focusId: string | null;
  openActivity: () => void;
  select: (
    key: string,
    id: string,
    origin: "map" | "activity",
    focusId?: string,
  ) => void;
  back: () => void;
  close: () => void;
  view: (v: Subview) => void;
}
export const useView = create<View>((set) => ({
  surface: "none",
  subview: "overview",
  selectedAttacker: null,
  selectedSession: null,
  origin: "map",
  feedScroll: 0,
  focusId: null,
  openActivity: () => set({ surface: "activity" }),
  select: (key, id, origin, focusId) =>
    set({
      surface: "creature",
      subview: "overview",
      selectedAttacker: key,
      selectedSession: id,
      origin,
      focusId: focusId ?? null,
    }),
  back: () => set({ subview: "overview" }),
  close: () =>
    set((s) =>
      s.surface === "creature"
        ? { surface: "activity", subview: "overview" }
        : { surface: "none" },
    ),
  view: (subview) => set({ subview }),
}));
