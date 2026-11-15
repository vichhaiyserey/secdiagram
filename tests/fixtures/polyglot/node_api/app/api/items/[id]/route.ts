export async function GET(request: Request, { params }: { params: { id: string } }) {
  return Response.json({ id: params.id });
}

export async function DELETE(request: Request) {
  const { searchParams } = new URL(request.url);
  const next = searchParams.get("next");
  // VULNERABLE: open redirect.
  return Response.redirect(next);
}
