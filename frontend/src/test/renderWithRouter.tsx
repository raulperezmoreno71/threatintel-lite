import type { ReactElement } from 'react'
import { render, type RenderOptions } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, type MemoryRouterProps } from 'react-router-dom'

type InitialEntry = NonNullable<MemoryRouterProps['initialEntries']>[number]

export type RenderWithRouterOptions = Omit<RenderOptions, 'wrapper'> & {
  route?: InitialEntry
}

export function renderWithRouter(
  ui: ReactElement,
  { route = '/', ...renderOptions }: RenderWithRouterOptions = {},
) {
  const user = userEvent.setup()

  return {
    user,
    ...render(
      <MemoryRouter initialEntries={[route]}>
        {ui}
      </MemoryRouter>,
      renderOptions,
    ),
  }
}
