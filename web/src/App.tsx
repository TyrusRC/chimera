import { useStore } from './store'
import { MainLayout } from './components/layout/MainLayout'
import { ProjectList } from './components/ProjectList'

export default function App() {
  const projectId = useStore((s) => s.currentProjectId)

  if (!projectId) {
    return <ProjectList />
  }

  return <MainLayout projectId={projectId} />
}
