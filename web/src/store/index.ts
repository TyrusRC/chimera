import { create } from 'zustand'

interface ChimeraState {
  currentProjectId: string | null
  selectedFunction: string | null
  sidebarTab: 'functions' | 'strings'

  setProject: (id: string | null) => void
  selectFunction: (address: string | null) => void
  setSidebarTab: (tab: 'functions' | 'strings') => void
}

export const useStore = create<ChimeraState>((set) => ({
  currentProjectId: null,
  selectedFunction: null,
  sidebarTab: 'functions',

  setProject: (id) => set({ currentProjectId: id, selectedFunction: null }),
  selectFunction: (address) => set({ selectedFunction: address }),
  setSidebarTab: (tab) => set({ sidebarTab: tab }),
}))
