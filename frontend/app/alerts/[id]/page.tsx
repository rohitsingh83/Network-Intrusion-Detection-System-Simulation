import ClientPage from './client-page';

export function generateStaticParams() {
  // Return at least one param to make export work, or we can use empty if Next 15 allows
  // Let's generate a dummy one.
  return [{ id: 'dummy' }];
}

export default async function AlertInvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const resolved = await params;
  return <ClientPage id={resolved.id} />;
}
