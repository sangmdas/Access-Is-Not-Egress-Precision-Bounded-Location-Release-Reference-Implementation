import pytest
from precision_egress.scenarios import stack, RAW
from precision_egress.factory import base_candidate
@pytest.fixture
def env(): return stack()
