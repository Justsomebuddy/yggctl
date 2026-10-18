"""Atlas command routing; no user-selected paths/URLs or automatic peering."""
from core import Failure, logged, bounded_number
import checks
from .store import Store
from . import catalogue, acquisition

VERSION = '1.0.1'


@logged
def command(ctx, args):
    if not args or args[0] not in ('catalogue','new','crawl','status','report') or len(args)>2:
        raise Failure('atlas_catalogue_new_crawl_status_report')
    action = args[0]
    if len(args)>1 and action != 'crawl': raise Failure('atlas_unexpected_argument')
    minutes = bounded_number(args[1],1,120) if len(args)>1 else None
    ctx.root(); checks.integrity(ctx)
    with Store(ctx, write=action in ('catalogue','new','crawl')) as store:
        if action == 'catalogue': return catalogue.acquire(ctx,store)
        if action == 'new': return {'run':acquisition.new_run(ctx,store), 'world_coverage':None}
        if action == 'crawl': return acquisition.crawl(ctx,store,minutes) if minutes is not None else acquisition.sweep(ctx,store)
        if action == 'status': return acquisition.status(store)
        from .analysis import report
        return report(ctx,store)
